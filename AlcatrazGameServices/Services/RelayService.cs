using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using Alcatraz.DTO.Models.v20260526;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using QNetZ;

namespace Alcatraz.GameServices.Services
{
    public interface IRelayService
    {
        bool IsEnabled { get; }
        string RealmIdHex { get; }
        List<RelayNodeInfo> GetPublicNodes();
        RelayDirectoryResponse GetDirectory(uint userId);
        RelayTicketResponse IssueTicket(uint userId, int? ttlSeconds = null);
        RelayServiceStatusResponse GetServiceStatus();
        Task<RelayResolveResponse> ResolvePeerAsync(
            string? clientKey,
            string? stormClientId,
            uint? userId,
            CancellationToken ct = default);
    }

    public class RelayService : IRelayService, IHostedService, IDisposable
    {
        private readonly ILogger<RelayService> _logger;
        private readonly IOptions<QConfiguration> _config;
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly object _keyLock = new object();
        private readonly object _nodesLock = new object();

        private ECDsa _signingKey;
        private string _pubKeyB64Url = string.Empty;
        private ulong _realmIdU64;
        private string _realmIdHex = string.Empty;

        private List<RelayNodeInfo> _nodeSnapshots = new List<RelayNodeInfo>();
        private CancellationTokenSource? _pollCts;
        private Task? _pollTask;

        public RelayService(
            ILogger<RelayService> logger,
            IOptions<QConfiguration> config,
            IHttpClientFactory httpClientFactory)
        {
            _logger = logger;
            _config = config;
            _httpClientFactory = httpClientFactory;

            _signingKey = LoadOrCreateSigningKey();
            InitializeNodeSnapshots();
        }

        public bool IsEnabled => _config.Value.RelayConfig.Enabled;
        public string RealmIdHex => _realmIdHex;

        private RelayConfig RelayCfg => _config.Value.RelayConfig;

        private string ResolveSigningKeyPath()
        {
            var rawPath = string.IsNullOrWhiteSpace(RelayCfg.SigningKeyPath)
                ? "relay_signing_key.pem"
                : RelayCfg.SigningKeyPath;

            if (Path.IsPathRooted(rawPath))
                return rawPath;

            var serverFiles = _config.Value.ServerFilesPath;
            if (string.IsNullOrWhiteSpace(serverFiles))
                serverFiles = "data/serverFiles";

            return Path.GetFullPath(Path.Combine(serverFiles, rawPath));
        }

        private ECDsa LoadOrCreateSigningKey()
        {
            var keyPath = ResolveSigningKeyPath();
            ECDsa ecdsa;

            if (File.Exists(keyPath))
            {
                var pem = File.ReadAllText(keyPath, Encoding.UTF8);
                ecdsa = ECDsa.Create();
                ecdsa.ImportFromPem(pem);
            }
            else
            {
                var dir = Path.GetDirectoryName(keyPath);
                if (!string.IsNullOrEmpty(dir))
                    Directory.CreateDirectory(dir);

                ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
                var pem = ecdsa.ExportPkcs8PrivateKeyPem();
                File.WriteAllText(keyPath, pem, new UTF8Encoding(false));

                if (!OperatingSystem.IsWindows())
                {
                    try
                    {
                        File.SetUnixFileMode(keyPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                    }
                    catch
                    {
                        // Ignore chmod failure on unsupported filesystems
                    }
                }
                _logger.LogInformation("Generated new federated ECDSA P-256 relay signing key at {Path}", keyPath);
            }

            var parameters = ecdsa.ExportParameters(false);
            if (parameters.Q.X == null || parameters.Q.Y == null || parameters.Q.X.Length != 32 || parameters.Q.Y.Length != 32)
            {
                throw new InvalidOperationException("Relay signing key must be an ECDSA P-256 keypair.");
            }

            // 65-byte SEC1 uncompressed public key: 0x04 || X(32) || Y(32)
            var pub65 = new byte[65];
            pub65[0] = 0x04;
            Buffer.BlockCopy(parameters.Q.X, 0, pub65, 1, 32);
            Buffer.BlockCopy(parameters.Q.Y, 0, pub65, 33, 32);

            _pubKeyB64Url = Base64UrlEncode(pub65);
            _realmIdU64 = DeriveRealmId(pub65);
            _realmIdHex = _realmIdU64.ToString("x16");

            return ecdsa;
        }

        private static ulong DeriveRealmId(byte[] pub65)
        {
            using var sha = SHA256.Create();
            var prefix = Encoding.ASCII.GetBytes("SRP-REALM-V2");
            var input = new byte[prefix.Length + pub65.Length];
            Buffer.BlockCopy(prefix, 0, input, 0, prefix.Length);
            Buffer.BlockCopy(pub65, 0, input, prefix.Length, pub65.Length);

            var digest = sha.ComputeHash(input);
            ulong id = 0;
            for (int i = 0; i < 8; i++)
            {
                id = (id << 8) | digest[i];
            }
            return id == 0 ? 1UL : id;
        }

        private static string Base64UrlEncode(byte[] bytes)
        {
            return Convert.ToBase64String(bytes)
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');
        }

        private void InitializeNodeSnapshots()
        {
            var initial = RelayCfg.Nodes.Select(n => new RelayNodeInfo
            {
                relayId = n.RelayId,
                name = string.IsNullOrWhiteSpace(n.Name) ? $"relay-{n.RelayId}" : n.Name,
                region = string.IsNullOrWhiteSpace(n.Region) ? "default" : n.Region,
                host = n.Host,
                udpPort = n.UdpPort,
                s2sAddr = n.S2sAddr ?? string.Empty,
                activePeers = 0,
                capacity = n.Capacity > 0 ? n.Capacity : 2000u,
                // Static nodes without an HttpBaseUrl are assumed reachable; HTTP-monitored nodes start healthy until first failure.
                healthy = true
            }).ToList();

            lock (_nodesLock)
            {
                _nodeSnapshots = initial;
            }
        }

        public RelayTicketResponse IssueTicket(uint userId, int? ttlSeconds = null)
        {
            if (!RelayCfg.Enabled || userId == 0)
            {
                return new RelayTicketResponse
                {
                    ticket = string.Empty,
                    realmId = _realmIdHex,
                    expiresAt = 0
                };
            }

            int ttl = ttlSeconds ?? RelayCfg.TicketTtlSeconds;
            if (ttl < 60)
                ttl = 60;
            if (ttl > 86400)
                ttl = 86400;

            long expiresAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + ttl;
            string payload = $"v2.{userId}.{expiresAt}.{_pubKeyB64Url}";
            byte[] payloadBytes = Encoding.ASCII.GetBytes(payload);

            byte[] sig64;
            lock (_keyLock)
            {
                sig64 = _signingKey.SignData(
                    payloadBytes,
                    HashAlgorithmName.SHA256,
                    DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            }

            return new RelayTicketResponse
            {
                ticket = $"{payload}.{Base64UrlEncode(sig64)}",
                realmId = _realmIdHex,
                expiresAt = expiresAt
            };
        }

        public List<RelayNodeInfo> GetPublicNodes()
        {
            if (!RelayCfg.Enabled)
                return new List<RelayNodeInfo>();

            lock (_nodesLock)
            {
                return _nodeSnapshots.Select(n => new RelayNodeInfo
                {
                    relayId = n.relayId,
                    name = n.name,
                    region = n.region,
                    host = n.host,
                    udpPort = n.udpPort,
                    s2sAddr = n.s2sAddr,
                    activePeers = n.activePeers,
                    capacity = n.capacity,
                    healthy = n.healthy
                }).ToList();
            }
        }

        public RelayDirectoryResponse GetDirectory(uint userId)
        {
            if (!RelayCfg.Enabled)
            {
                return new RelayDirectoryResponse
                {
                    relays = new List<RelayNodeInfo>(),
                    ticket = string.Empty,
                    realmId = string.Empty,
                    expiresAt = 0
                };
            }

            List<RelayNodeInfo> relays;
            lock (_nodesLock)
            {
                relays = _nodeSnapshots.Select(n => new RelayNodeInfo
                {
                    relayId = n.relayId,
                    name = n.name,
                    region = n.region,
                    host = n.host,
                    udpPort = n.udpPort,
                    s2sAddr = n.s2sAddr,
                    activePeers = n.activePeers,
                    capacity = n.capacity,
                    healthy = n.healthy
                }).ToList();
            }

            var ticketResp = IssueTicket(userId);
            return new RelayDirectoryResponse
            {
                relays = relays,
                ticket = ticketResp.ticket,
                realmId = ticketResp.realmId,
                expiresAt = ticketResp.expiresAt
            };
        }

        public RelayServiceStatusResponse GetServiceStatus()
        {
            lock (_nodesLock)
            {
                return new RelayServiceStatusResponse
                {
                    enabled = RelayCfg.Enabled,
                    realmId = _realmIdHex,
                    nodeCount = _nodeSnapshots.Count,
                    healthyNodeCount = _nodeSnapshots.Count(n => n.healthy)
                };
            }
        }

        public async Task<RelayResolveResponse> ResolvePeerAsync(
            string? clientKey,
            string? stormClientId,
            uint? userId,
            CancellationToken ct = default)
        {
            var notFound = new RelayResolveResponse { found = false };
            if (!RelayCfg.Enabled)
                return notFound;

            var queryParts = new List<string> { $"realmId={Uri.EscapeDataString(_realmIdHex)}" };
            if (!string.IsNullOrWhiteSpace(clientKey))
                queryParts.Add($"clientKey={Uri.EscapeDataString(clientKey)}");
            else if (!string.IsNullOrWhiteSpace(stormClientId))
                queryParts.Add($"stormClientId={Uri.EscapeDataString(stormClientId)}");
            else if (userId.HasValue && userId.Value != 0)
                queryParts.Add($"userId={userId.Value}");
            else
                return notFound;

            var qs = string.Join("&", queryParts);
            var nodes = RelayCfg.Nodes.Where(n => !string.IsNullOrWhiteSpace(n.HttpBaseUrl)).ToList();
            if (nodes.Count == 0)
                return notFound;

            var client = _httpClientFactory.CreateClient("RelayHealth");
            client.Timeout = TimeSpan.FromSeconds(4);

            foreach (var node in nodes)
            {
                try
                {
                    var url = $"{node.HttpBaseUrl.TrimEnd('/')}/v1/relay/resolve?{qs}";
                    var resp = await client.GetFromJsonAsync<RelayResolveResponse>(url, ct);
                    if (resp != null && resp.found)
                        return resp;
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "Relay resolve query failed for node {RelayId}", node.RelayId);
                }
            }

            return notFound;
        }

        public Task StartAsync(CancellationToken cancellationToken)
        {
            if (!RelayCfg.Enabled || (RelayCfg.Nodes.All(n => string.IsNullOrWhiteSpace(n.HttpBaseUrl)) && string.IsNullOrWhiteSpace(RelayCfg.UpstreamDirectoryUrl)))
                return Task.CompletedTask;

            _pollCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            _pollTask = Task.Run(() => PollLoopAsync(_pollCts.Token), _pollCts.Token);
            return Task.CompletedTask;
        }

        public async Task StopAsync(CancellationToken cancellationToken)
        {
            if (_pollCts != null)
            {
                _pollCts.Cancel();
                if (_pollTask != null)
                {
                    try
                    {
                        await _pollTask.WaitAsync(cancellationToken);
                    }
                    catch (OperationCanceledException)
                    {
                    }
                }
            }
        }

        private async Task PollLoopAsync(CancellationToken ct)
        {
            while (!ct.IsCancellationRequested)
            {
                await PollNodesOnceAsync(ct);

                int intervalSec = RelayCfg.HealthPollIntervalSeconds;
                if (intervalSec < 3)
                    intervalSec = 3;

                try
                {
                    await Task.Delay(TimeSpan.FromSeconds(intervalSec), ct);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
            }
        }

        private async Task PollNodesOnceAsync(CancellationToken ct)
        {
            var configured = RelayCfg.Nodes;
            var client = _httpClientFactory.CreateClient("RelayHealth");
            client.Timeout = TimeSpan.FromSeconds(4);

            var updated = new List<RelayNodeInfo>(configured.Count);
            if (!string.IsNullOrWhiteSpace(RelayCfg.UpstreamDirectoryUrl))
            {
                try
                {
                    using var resp = await client.GetAsync(RelayCfg.UpstreamDirectoryUrl, ct);
                    if (resp.IsSuccessStatusCode)
                    {
                        var body = await resp.Content.ReadAsStringAsync(ct);
                        var jsonOpts = new System.Text.Json.JsonSerializerOptions { PropertyNameCaseInsensitive = true };
                        var wrapped = System.Text.Json.JsonSerializer.Deserialize<ApiResponse<List<RelayNodeInfo>>>(body, jsonOpts);
                        List<RelayNodeInfo>? upstreamNodes = wrapped?.Data;
                        if (upstreamNodes == null)
                        {
                            upstreamNodes = System.Text.Json.JsonSerializer.Deserialize<List<RelayNodeInfo>>(body, jsonOpts);
                        }
                        if (upstreamNodes != null)
                        {
                            updated.AddRange(upstreamNodes);
                        }
                    }
                }
                catch (Exception ex) when (!ct.IsCancellationRequested)
                {
                    _logger.LogDebug(ex, "Upstream relay directory sync failed ({Url})", RelayCfg.UpstreamDirectoryUrl);
                }
            }

            foreach (var node in configured)
            {
                var info = new RelayNodeInfo
                {
                    relayId = node.RelayId,
                    name = string.IsNullOrWhiteSpace(node.Name) ? $"relay-{node.RelayId}" : node.Name,
                    region = string.IsNullOrWhiteSpace(node.Region) ? "default" : node.Region,
                    host = node.Host,
                    udpPort = node.UdpPort,
                    s2sAddr = node.S2sAddr ?? string.Empty,
                    activePeers = 0,
                    capacity = node.Capacity > 0 ? node.Capacity : 2000u,
                    healthy = true
                };

                if (!string.IsNullOrWhiteSpace(node.HttpBaseUrl))
                {
                    try
                    {
                        var url = $"{node.HttpBaseUrl.TrimEnd('/')}/v1/relay/health";
                        var health = await client.GetFromJsonAsync<RelayNodeHealthDto>(url, ct);
                        if (health != null && string.Equals(health.Status, "ok", StringComparison.OrdinalIgnoreCase))
                        {
                            info.healthy = true;
                            info.activePeers = (uint)Math.Max(0, health.LocalClients);
                            if (health.Capacity > 0)
                                info.capacity = health.Capacity;
                            if (!string.IsNullOrWhiteSpace(health.Name))
                                info.name = health.Name;
                            if (!string.IsNullOrWhiteSpace(health.Region))
                                info.region = health.Region;
                        }
                        else
                        {
                            info.healthy = false;
                        }
                    }
                    catch (Exception ex) when (!ct.IsCancellationRequested)
                    {
                        info.healthy = false;
                        _logger.LogDebug(ex, "Health check failed for relay node {RelayId} ({Url})", node.RelayId, node.HttpBaseUrl);
                    }
                }

                var existingIdx = updated.FindIndex(x => x.relayId == info.relayId);
                if (existingIdx >= 0)
                    updated[existingIdx] = info;
                else
                    updated.Add(info);
            }

            lock (_nodesLock)
            {
                _nodeSnapshots = updated;
            }
        }

        public void Dispose()
        {
            _pollCts?.Dispose();
            _signingKey.Dispose();
        }

        private sealed class RelayNodeHealthDto
        {
            [JsonPropertyName("status")]
            public string Status { get; set; } = string.Empty;

            [JsonPropertyName("relayId")]
            public ushort RelayId { get; set; }

            [JsonPropertyName("name")]
            public string Name { get; set; } = string.Empty;

            [JsonPropertyName("region")]
            public string Region { get; set; } = string.Empty;

            [JsonPropertyName("localClients")]
            public int LocalClients { get; set; }

            [JsonPropertyName("capacity")]
            public uint Capacity { get; set; }
        }
    }
}
