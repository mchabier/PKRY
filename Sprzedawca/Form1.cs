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

namespace Sprzedawca
{
    public partial class Sprzedawca : Form
    {
        public static TextWriter _writer = null;
        public static Serwer serwer = null;
        public Sprzedawca()
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

        private void button2_Click_1(object sender, EventArgs e)
        {

        }

        private void textBox1_TextChanged(object sender, EventArgs e)
        {

        }
        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            serwer.listener.Close();
            base.OnFormClosing(e);
            System.Windows.Forms.Application.Exit();
        }
    }
}
