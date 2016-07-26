using System.Runtime.Serialization;

namespace AP.ASP.Infratec.Models
{
    [DataContract]
    public class InfratecData
    {
        [DataMember]
        public bool MethodResult;

        [DataMember]
        public string CultureCode;

        [DataMember]
        public string CultureDescription;

        [DataMember]
        public string[] AnalisisResult;

    }

}
