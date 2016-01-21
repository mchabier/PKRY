using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace BramaPlatnosci
{
    static class Program
    {
        public static BramaPlatnosci brama;
        /// <summary>
        /// The main entry point for the application.
        /// </summary>
        [STAThread]
        static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            brama = new BramaPlatnosci();
            
            Application.Run(brama);
        }
    }
}
