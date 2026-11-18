using System.Collections.Generic;

namespace Alcatraz.DTO.Models.v20260526
{
    public class RelayNodeInfo
    {
        public ushort relayId { get; set; }
        public string name { get; set; } = string.Empty;
        public string region { get; set; } = string.Empty;
        public string host { get; set; } = string.Empty;
        public ushort udpPort { get; set; }
        public string s2sAddr { get; set; } = string.Empty;
        public uint activePeers { get; set; }
        public uint capacity { get; set; }
        public bool healthy { get; set; }
    }

    public class RelayDirectoryResponse
    {
        public List<RelayNodeInfo> relays { get; set; } = new List<RelayNodeInfo>();
        public string ticket { get; set; } = string.Empty;
        public string realmId { get; set; } = string.Empty;
        public long expiresAt { get; set; }
    }

    public class RelayTicketResponse
    {
        public string ticket { get; set; } = string.Empty;
        public string realmId { get; set; } = string.Empty;
        public long expiresAt { get; set; }
    }

    public class RelayResolveResponse
    {
        public bool found { get; set; }
        public ushort homeRelayId { get; set; }
        public string clientKey { get; set; } = "0";
        public string stormClientId { get; set; } = "0";
        public string virtualIpv4 { get; set; } = string.Empty;
        public bool allowDirect { get; set; }
    }

    public class RelayServiceStatusResponse
    {
        public bool enabled { get; set; }
        public string realmId { get; set; } = string.Empty;
        public int nodeCount { get; set; }
        public int healthyNodeCount { get; set; }
    }
}
