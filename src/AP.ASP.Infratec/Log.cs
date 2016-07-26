using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Web.Compilation;

namespace AP.ASP.Infratec
{
    internal class Log
    {
        private static object sync = new object();
        public static void Write(string exDeclaringType, string exName, string exMessage)
        {
            try
            {
                // Путь .\\Log
                //BuildManager.GetGlobalAsaxType().BaseType.Assembly.GetName().Name
                string pathToLog = Path.Combine(Path.GetTempPath(), "AP.ASP.Infratec");
                if (!Directory.Exists(pathToLog))
                    Directory.CreateDirectory(pathToLog); // Создаем директорию, если нужно
                string filename = Path.Combine(pathToLog, string.Format("{0}_{1:dd.MM.yyy}.log",
                "AP.ASP.Infratec", DateTime.Now));
                string fullText = string.Format("[{0:dd.MM.yyy HH:mm:ss.fff}] [{1}.{2}()] {3}\r\n",
                DateTime.Now, exDeclaringType, exName, exMessage);
                lock (sync)
                {
                    File.AppendAllText(filename, fullText, Encoding.GetEncoding("Windows-1251"));
                }
            }
            catch
            {
                // Перехватываем все и ничего не делаем
            }
        }
    }


}
