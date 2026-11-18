using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Alcatraz.DTO.Models;
using Alcatraz.DTO.Models.v20260526;
using Alcatraz.GameServices.Helpers;
using Alcatraz.GameServices.Services;
using Microsoft.AspNetCore.Mvc;

namespace Alcatraz.GameServices.Controllers.v20260526
{
    [ApiController]
    [Route("api/v{version}/relay")]
    public class RelayController : ControllerBase
    {
        private readonly IRelayService _relayService;

        public RelayController(IRelayService relayService)
        {
            _relayService = relayService;
        }

        [Authorize]
        [HttpGet("directory")]
        public IActionResult GetDirectory()
        {
            var user = (UserModel)HttpContext.Items["User"];
            if (user == null)
            {
                return ApiErrorHelper.CreateErrorResult(
                    HttpContext,
                    TNTMPErrorCode.SERVER_Unauthorized,
                    "Session expired.",
                    (int)HttpStatusCode.Unauthorized);
            }

            return Ok(_relayService.GetDirectory(user.Id));
        }

        [Authorize]
        [HttpPost("ticket")]
        public IActionResult IssueTicket()
        {
            var user = (UserModel)HttpContext.Items["User"];
            if (user == null)
            {
                return ApiErrorHelper.CreateErrorResult(
                    HttpContext,
                    TNTMPErrorCode.SERVER_Unauthorized,
                    "Session expired.",
                    (int)HttpStatusCode.Unauthorized);
            }

            return Ok(_relayService.IssueTicket(user.Id));
        }

        [Authorize]
        [HttpGet("resolve")]
        public async Task<IActionResult> Resolve(
            [FromQuery] string? clientKey,
            [FromQuery] string? stormClientId,
            [FromQuery] uint? userId,
            CancellationToken ct)
        {
            var user = (UserModel)HttpContext.Items["User"];
            if (user == null)
            {
                return ApiErrorHelper.CreateErrorResult(
                    HttpContext,
                    TNTMPErrorCode.SERVER_Unauthorized,
                    "Session expired.",
                    (int)HttpStatusCode.Unauthorized);
            }

            var resolved = await _relayService.ResolvePeerAsync(clientKey, stormClientId, userId, ct);
            return Ok(resolved);
        }

        [HttpGet("nodes")]
        public IActionResult GetNodes()
        {
            return Ok(_relayService.GetPublicNodes());
        }

        [HttpGet("health")]
        public IActionResult Health()
        {
            return Ok(_relayService.GetServiceStatus());
        }
    }
}
