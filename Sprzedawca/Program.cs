using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace Sprzedawca
{
    static class Program
    {
        public static Sprzedawca sprzedawca = null;
        /// <summary>
        /// The main entry point for the application.
        /// </summary>
        [STAThread]
        static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            sprzedawca = new Sprzedawca();
            Application.Run(sprzedawca);
        }
    }
}
