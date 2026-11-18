using System.Collections.Generic;
using QNetZ;
using QNetZ.Attributes;
using QNetZ.Interfaces;

namespace DSFServices.Services
{
    [RMCService(RMCProtocolId.NexusOnly, Name = "NexusWallaProtocol")]
    public class NexusWallaProtocol : RMCServiceBase
    {
        [RMCMethod(0, "UpdateCheckinStatus_V3")]
        public RMCResult UpdateCheckinStatus()
        {
            return Error(0);
        }
        
        [RMCMethod(0, "GetMayorForLocation_V2")]
        public RMCResult GetMayorForLocation()
        {
            return Error(0);
        }
        
        [RMCMethod(0, "GetSpotGifts_V1")]
        public RMCResult GetSpotGifts()
        {
            return Error(0);
        }
        
        [RMCMethod(0, "GetEconomyInfo_V1")]
        public RMCResult GetEconomyInfo()
        {
            return Error(0);
        }
        
        [RMCMethod(0, "UpdateVisitedLocations_V1")]
        public RMCResult UpdateVisitedLocations()
        {
            return Error(0);
        }
        
        [RMCMethod(0, "IncrementClaimedGifts_V1")]
        public RMCResult IncrementClaimedGifts()
        {
            return Error(0);
        }
        
        [RMCMethod(0, "AddGiftToSpot_V5")]
        public RMCResult AddGiftToSpot()
        {
            return Error(0);
        }
    }
}