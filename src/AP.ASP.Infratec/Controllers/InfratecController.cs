using System;
using Microsoft.AspNet.Mvc;
using System.Net.NetworkInformation;
using System.Net;
using System.Text;
using System.Net.Sockets;
using System.Threading;
using AP.ASP.Infratec.Models;


// For more information on enabling MVC for empty projects, visit http://go.microsoft.com/fwlink/?LinkID=397860

namespace AP.ASP.Infratec.Controllers
{
    public class InfratecController : Controller
    {

        [HttpGet]
        public ActionResult GetGrainAnalyze(string infratecIp, int port, int labTimeout, int pingTimeout, int pingCount)
        {
            Ping pingSender = new Ping();
            PingOptions options = new PingOptions();
            InfratecData infratecData = new InfratecData();
            JsonOutputFormatter json = new JsonOutputFormatter();
            Log.Write("Infratec", "GetGrainAnalyze", String.Format("InfratecIP={0}, InfratecPort={1}, Timeout={2}, PingTimeout={3}, PingCount={4}", infratecIp, port, labTimeout * 10, pingTimeout, pingCount));
            //Log.Write("Infratec", "GetGrainAnalyze", BuildManager.GetGlobalAsaxType().BaseType.Assembly.GetName().Name);
            try
            {
                IPAddress.Parse(infratecIp);
            }
            catch (Exception ex)
            {
                Log.Write(ex.Source, ex.StackTrace, ex.Message);
                Log.Write("Infratec", "GetGrainAnalyze", "Return result");
                infratecData.MethodResult = false;
                infratecData.AnalisisResult = new string[] { ex.Message };
                return new JsonResult(infratecData);
            }
            // Use the default Ttl value which is 128,
            // but change the fragmentation behavior.
            options.DontFragment = true;

            // Create a buffer of 32 bytes of data to be transmitted.
            string pingData = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
            byte[] buffer = Encoding.ASCII.GetBytes(pingData);
            PingReply reply = null;
            bool pingReply = false;
            if (pingTimeout > 0 && pingCount > 0)
            {
                for (int i = 0; i < pingCount; i++)
                {
                    Log.Write("Infratec", "GetGrainAnalyze", String.Format("Send ping request to {0}({1})", infratecIp, i + 1));
                    reply = pingSender.Send(infratecIp, pingTimeout, buffer, options);
                    if (reply.Status == IPStatus.Success)
                    {
                        pingReply = true;
                        Log.Write("Infratec", "GetGrainAnalyze", "Ping successful!");
                        break;
                    }
                }
            }
            if (pingTimeout == 0 || pingCount == 0 || pingReply)
            {
                TcpListener infratecListner = new TcpListener(IPAddress.Any, port);
                string data = String.Empty;
                try
                {
                    Log.Write("Infratec", "GetGrainAnalyze", String.Format("Open port {0}\r\nWait for data...", port));
                    infratecListner.Start();
                    Byte[] bytes = new Byte[256];
                    for (int current = 0; current < labTimeout * 10; current++)
                    {
                        Thread.Sleep(100);
                        //Application.DoEvents();
                        if (infratecListner.Pending())
                        {
                            Log.Write("Infratec", "GetGrainAnalyze", "Data pending...");
                            TcpClient infratecClient = infratecListner.AcceptTcpClient();
                            //throw new Exception((((IPEndPoint)infratecClient.Client.RemoteEndPoint).Address).ToString() + " - " + (((IPEndPoint)infratecClient.Client.RemoteEndPoint).Address).ToString());
                            if (infratecIp == (((IPEndPoint)infratecClient.Client.RemoteEndPoint).Address).ToString())
                            {
                                Log.Write("Infratec", "GetGrainAnalyze", "Datasource authorized.\r\nReading data...");
                                //infratecClient.ReceiveTimeout = 10000;
                                NetworkStream dataStream = infratecClient.GetStream();
                                int i;

                                // Loop to receive all the data sent by the client.
                                while ((i = dataStream.Read(bytes, 0, bytes.Length)) != 0)
                                {
                                    // Translate data bytes to a ASCII string.
                                    data += System.Text.Encoding.UTF8.GetString(bytes, 0, i);
                                }
                                Log.Write("Infratec", "GetGrainAnalyze", String.Format("Recieved {0} bytes", bytes.Length));
                                Log.Write("Infratec", "GetGrainAnalyze", data);
                            }
                            infratecClient.Close();
                        }
                        else if (data.Length > 0)
                            break;
                    }
                }
                catch (Exception ex)
                {
                    Log.Write(ex.Source, ex.StackTrace, ex.Message);
                    Log.Write("Infratec", "GetGrainAnalyze", String.Format("Closing {0} port...", port));
                    infratecListner.Stop();
                    Log.Write("Infratec", "GetGrainAnalyze", "Return result");
                    infratecData.MethodResult = false;
                    infratecData.AnalisisResult = new string[] { ex.Message };
                    return new JsonResult(infratecData);
                }
                finally
                {
                    Log.Write("Infratec", "GetGrainAnalyze", String.Format("Closing {0} port...", port));
                    infratecListner.Stop();
                }
                Log.Write("Infratec", "GetGrainAnalyze", "Analize recieved data...");

                string snRegex = "/ApplicationModel=String,";
                string descriptionRegex = "/AmDescription=String,";
                string criteriousRegex = "/Name=String,";
                string resultRegex = "/PredictedValue=Number,";
                string criterions = String.Empty;
                string results = String.Empty;


                foreach (var line in data.Split(new string[] { Environment.NewLine }, StringSplitOptions.RemoveEmptyEntries))
                {
                    if (line.LastIndexOf(snRegex) > -1)
                    {
                        infratecData.CultureCode += line.Substring(line.LastIndexOf(snRegex) + snRegex.Length).Replace("\"", String.Empty);
                    }
                    if (line.LastIndexOf(descriptionRegex) > -1)
                    {
                        infratecData.CultureDescription += line.Substring(line.LastIndexOf(descriptionRegex) + descriptionRegex.Length).Replace("\"", String.Empty);
                    }

                    if (line.LastIndexOf(criteriousRegex) > -1)
                    {
                        criterions += line.Substring(line.LastIndexOf(criteriousRegex) + criteriousRegex.Length).Replace("\"", String.Empty) + ";";
                    }
                    if (line.LastIndexOf(resultRegex) > -1)
                    {
                        results += line.Substring(line.LastIndexOf(resultRegex) + resultRegex.Length) + ";";
                    }
                }
                string[] criterionsArray = criterions.Split(new char[] { ';' }, StringSplitOptions.RemoveEmptyEntries);
                string[] resultsArray = results.Split(new char[] { ';' }, StringSplitOptions.RemoveEmptyEntries);
                string[] analisisResult = new string[criterionsArray.Length];
                for (int count = 0; count < criterionsArray.Length; count++)
                {
                    if (!String.IsNullOrEmpty(criterionsArray[count]) && !String.IsNullOrWhiteSpace(criterionsArray[count])
                        && !String.IsNullOrEmpty(resultsArray[count]) && !String.IsNullOrWhiteSpace(resultsArray[count]))
                    {
                        analisisResult[count] = criterionsArray[count] + "=" + resultsArray[count];
                    }
                }
                if (analisisResult.Length > 0)
                {
                    Log.Write("Infratec", "GetGrainAnalyze", "Return result");
                    infratecData.MethodResult = true;
                    infratecData.AnalisisResult = analisisResult;
                    return new JsonResult(infratecData);
                }
                else
                {
                    Log.Write("Infratec", "GetGrainAnalyze", "Return result");
                    infratecData.MethodResult = false;
                    return new JsonResult(infratecData);
                }
            }
            else
            {
                Log.Write("Infratec", "GetGrainAnalyze", "Return result");
                infratecData.MethodResult = true;
                infratecData.AnalisisResult = new string[] { "Ping Timeout (" + infratecIp + ")" };
                return new JsonResult(infratecData);
            }
        }

    }
}
