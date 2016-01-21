using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace BramaPlatnosci
{
    public partial class BramaPlatnosci : Form
    {
        public static TextWriter _writer = null;
        public static Serwer serwer = null;
        public BramaPlatnosci()
        {
            InitializeComponent();
            _writer = new TextBoxStreamWriter(textBox1);
            Console.SetOut(_writer);
        }

        private void button1_Click(object sender, EventArgs e)
        {
            serwer = new Serwer();
            Thread t = new Thread(serwer.StartSerwer);
            t.Start();
            //serwer.StartSerwer();

        }
        public void WpiszDoTextBoxa(string value)
        {
            MethodInvoker action = delegate
            { _writer.WriteLine(value); }; //textBox1.Text += value;
            textBox1.BeginInvoke(action);
        }
        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            if(serwer != null)
                if(serwer.listener != null)
                    serwer.listener.Close();
            base.OnFormClosing(e);
            System.Windows.Forms.Application.Exit();
        }
    }
}
