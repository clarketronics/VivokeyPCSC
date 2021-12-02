using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using PCSC;
using PCSC.Iso7816;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text;

namespace Vivokey_ChipScan
{
    class ChipScan
    {
        // Constants for the class hopefully self explanatory, there just the endpoints
        private const string baseURL = "https://api2.vivokey.com/v1/";
        private const string getChallengeEndpoint = "get-challenge";
        private const string pcdChallengeEndpoint = "pcd-challenge";
        private const string checkResponseEndpoint = "check-response";

        ContextFactory _contextFactory; // PCSC context factory (smartcard readers).

        // Variables for the class.
        private string _apikey;
        private string _reader;
        private string PICCUID;
        private string PICCchallenge;
        private string PICCresponse;
        private string PCDchallenge;
        private string PCDresponse;

        // Tag type enum Spark1 not used as acr122u cannot use it.
        private enum TagType
        {
            Spark2,
            Apex
        }

        // Variables the caller can access.
        public string result;
        public string resultData;

        // This is the class constructor, this code is called when we create an new instance.
        public ChipScan(string apikey, string reader, ContextFactory contextFactory)
        {
            _apikey = apikey; // Set our api key to the one fed in.
            _reader = reader; // Set reader name from the one fed in.
            _contextFactory = contextFactory; // Smartcard reader context.
        }

        public bool ChipScanned()
        {
            ClearResults();
            GetPICCchallenge();
            GetUID();
            GetPCDChallenge();
            GetPCDResponse();
            SendPCDResponse();
            CheckResult();

            return true;
        }

        // Obtain a challenge from the api / server.
        private void GetPICCchallenge()
        {
            string challenge;
            var httpWebRequest = (HttpWebRequest)WebRequest.Create(baseURL + getChallengeEndpoint);
            httpWebRequest.ContentType = "application/json";
            httpWebRequest.Method = "POST";

            using (var streamWriter = new StreamWriter(httpWebRequest.GetRequestStream()))
            {
                Dictionary<string, string> post = new Dictionary<string, string>
                {
                    {"api-key", _apikey }
                };

                string json = JsonConvert.SerializeObject(post);

                streamWriter.Write(json);
            }

            var httpResponse = (HttpWebResponse)httpWebRequest.GetResponse();
            using (var streamReader = new StreamReader(httpResponse.GetResponseStream()))
            {
                challenge = streamReader.ReadToEnd();
            }
            
            PICCchallenge = JObject.Parse(challenge)["picc-challenge"].ToString();

        }
        
        // Read the UID of the chip presented.
        private void GetUID()
        {
            using (var ctx = _contextFactory.Establish(SCardScope.System))
            {
                using (var isoReader = new IsoReader(ctx, _reader, SCardShareMode.Shared, SCardProtocol.Any, false))
                {
                    var getUIDAPDU = new CommandApdu(IsoCase.Case2Short, isoReader.ActiveProtocol)
                    {
                        CLA = 0xFF,
                        Instruction = InstructionCode.GetData,
                        P1 = 0x00,
                        P2 = 0x00,
                        Le = 0x00
                    };

                    PICCUID = ReverseStringByteOrder(BitConverter.ToString(isoReader.Transmit(getUIDAPDU).GetData()).Replace("-", string.Empty));
                }
            }
        }

        // Get a challenge from the scanned device (only used in some conditions i.e. spark2).
        private void GetPCDChallenge()
        {
            using (var ctx = _contextFactory.Establish(SCardScope.System))
            {
                using (var isoReader = new IsoReader(ctx, _reader, SCardShareMode.Shared, SCardProtocol.Any, false))
                {

                    var selectFile = new CommandApdu(IsoCase.Case3Short, SCardProtocol.Any)
                    {
                        CLA = 0x00,
                        INS = 0xA4,
                        P1 = 0x04,
                        P2 = 0x0C,
                        Data = new byte[] { 0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01 }
                    };

                    var slecectFileResponse = isoReader.Transmit(selectFile);

                    var authenticateFirstPart1 = new CommandApdu(IsoCase.Case4Short, isoReader.ActiveProtocol)
                    {
                        CLA = 0x90,
                        INS = 0x71,
                        P1 = 0x00,
                        P2 = 0x00,
                        Data = new byte[] { 0x02, 0x00 },
                        Le = 0x00
                    };

                    PCDchallenge = BitConverter.ToString(isoReader.Transmit(authenticateFirstPart1).GetData()).Replace("-", string.Empty);
                }
            }
        }

        // Get the response to send to the scanned device (only used in some conditions i.e. spark2).
        private void GetPCDResponse()
        {
            string jsonResponse;
            var httpWebRequest = (HttpWebRequest)WebRequest.Create(baseURL + pcdChallengeEndpoint);
            httpWebRequest.ContentType = "application/json";
            httpWebRequest.Method = "POST";

            using (var streamWriter = new StreamWriter(httpWebRequest.GetRequestStream()))
            {
                Dictionary<string, string> post = new Dictionary<string, string>
                {
                    {"picc-uid", PICCUID },
                    {"picc-challenge", PICCchallenge },
                    {"pcd-challenge", PCDchallenge }
                };

                string json = JsonConvert.SerializeObject(post, Formatting.Indented);

                streamWriter.Write(json);
            }

            var httpResponse = (HttpWebResponse)httpWebRequest.GetResponse();
            using (var streamReader = new StreamReader(httpResponse.GetResponseStream()))
            {
                jsonResponse = streamReader.ReadToEnd();
            }

            PCDresponse = JObject.Parse(jsonResponse)["pcd-response"].ToString();
        }

        // Send the response from the server to the scanned device.
        private void SendPCDResponse()
        {
            using (var ctx = _contextFactory.Establish(SCardScope.System))
            {
                using (var isoReader = new IsoReader(ctx, _reader, SCardShareMode.Shared, SCardProtocol.Any, false))
                {

                    var authenticateFirstPart2 = new CommandApdu(IsoCase.Case4Short, isoReader.ActiveProtocol)
                    {
                        CLA = 0x90,
                        INS = 0xaf,
                        P1 = 0x00,
                        P2 = 0x00,
                        Data = StringToHex(PCDresponse),
                        Le = 0x00
                    };

                    PICCresponse = BitConverter.ToString(isoReader.Transmit(authenticateFirstPart2).GetData()).Replace("-", string.Empty);
                }
            }
        }

        private void CheckResult()
        {
            string jsonResponse;
            var httpWebRequest = (HttpWebRequest)WebRequest.Create(baseURL + checkResponseEndpoint);
            httpWebRequest.ContentType = "application/json";
            httpWebRequest.Method = "POST";

            using (var streamWriter = new StreamWriter(httpWebRequest.GetRequestStream()))
            {
                Dictionary<string, string> post = new Dictionary<string, string>
            {
                {"picc-uid", PICCUID },
                {"picc-challenge", PICCchallenge },
                {"picc-response", PICCresponse}
            };

                string json = JsonConvert.SerializeObject(post, Formatting.Indented);

                streamWriter.Write(json);
            }

            var httpResponse = (HttpWebResponse)httpWebRequest.GetResponse();
            using (var streamReader = new StreamReader(httpResponse.GetResponseStream()))
            {
                jsonResponse = streamReader.ReadToEnd();
            }

            result = JObject.Parse(jsonResponse)["check-result"].ToString();
            resultData = JObject.Parse(jsonResponse)["result-data"].ToString();
        }

        // Helper function for reversing hex data stored in a string.
        private string ReverseStringByteOrder(string hexString)
        {
            byte[] array = StringToHex(hexString);
            Array.Reverse(array, 0, array.Length);

            return BitConverter.ToString(array).Replace("-", string.Empty);
        }

        // Helper function for converting string to a array of hex bytes.
        private byte[] StringToHex(string hexstring)
        {
            Dictionary<char, byte> hexmap = new Dictionary<char, byte>()
            {
                { 'a', 0xA },{ 'b', 0xB },{ 'c', 0xC },{ 'd', 0xD },
                { 'e', 0xE },{ 'f', 0xF },{ 'A', 0xA },{ 'B', 0xB },
                { 'C', 0xC },{ 'D', 0xD },{ 'E', 0xE },{ 'F', 0xF },
                { '0', 0x0 },{ '1', 0x1 },{ '2', 0x2 },{ '3', 0x3 },
                { '4', 0x4 },{ '5', 0x5 },{ '6', 0x6 },{ '7', 0x7 },
                { '8', 0x8 },{ '9', 0x9 }
            };

            byte[] data = new byte[hexstring.Length / 2];
            char one, two;

            int x = 0;
            for (int i = 0; i < hexstring.Length; i += 2, x++)
            {
                one = hexstring[i];
                two = hexstring[i + 1];
                data[x] = (byte)((hexmap[one] << 4) | hexmap[two]);
            }

            return data;
        }

        // Helper function for clearing the results.
        private void ClearResults()
        {
            result = "";
            resultData = "";
        }
    }
}
