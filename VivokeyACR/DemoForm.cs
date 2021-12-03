using System;
using System.Windows.Forms;
using PCSC;
using PCSC.Iso7816;
using Vivokey_ChipScan;
using PCSC.Monitoring;

namespace VivokeyACR
{
    public partial class DemoForm : Form
    {
        private const string apikey = "";
        ContextFactory contextFactory = new ContextFactory();
        MonitorFactory monitorFactory = new MonitorFactory(new ContextFactory());
        ISCardMonitor monitor;
        bool result;

        ChipScan chipScan;
        Form form1;

        public DemoForm()
        {
            InitializeComponent();
            monitor = monitorFactory.Create(SCardScope.System);
            monitor.CardInserted += Monitor_CardInserted;
            form1 = this;
        }

        private void Monitor_CardInserted(object sender, CardStatusEventArgs e)
        {
            result = chipScan.ChipScanned();

            form1.BeginInvoke((MethodInvoker)delegate ()
            {
                RefreshLabels();
                ResultsUpdated();
            });
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            RefreshReaders();
            RefreshLabels();
            chipScan = new ChipScan(apikey, readersComboBox.Text, contextFactory);
        }

        private void refreshButton_Click(object sender, EventArgs e)
        {
            RefreshReaders();
        }

        private void button3_Click(object sender, EventArgs e)
        {
            using (var ctx = contextFactory.Establish(SCardScope.System))
            {
                using (var isoReader = new IsoReader(ctx, readersComboBox.Text, SCardShareMode.Exclusive, SCardProtocol.Any, false))
                {

                    var apdu = new CommandApdu(IsoCase.Case4Short, isoReader.ActiveProtocol)
                    {
                        CLA = 0xFF, // Class
                        INS = 0x00,
                        P1 = 0x40,
                        P2 = 0xAA,
                        Data = new byte[] { 0x01, 0x01, 0x03, 0x00},
                        Le = 0x00
                    };

                    var response = isoReader.Transmit(apdu);
                }
            }
        }

        private void RefreshReaders()
        {
            using (var conText = contextFactory.Establish(SCardScope.System))
            {
                readersComboBox.Items.Clear();
                var readerNames = conText.GetReaders();
                foreach (var readerName in readerNames)
                {
                    readersComboBox.Items.Add(readerName);
                    readersComboBox.SelectedIndex = 0;
                }
            }
        }
       
        public void RefreshLabels()
        {
            label5.Text = "device type: ";
            label6.Text = "check result: ";
            label7.Text = "result data: ";
        }

        private void ResultsUpdated()
        {
            if (result)
            {
                label5.Text = label5.Text + chipScan.tagType;
                label6.Text = label6.Text + chipScan.result;
                label7.Text = label7.Text + chipScan.resultData;
            }
            else
            {
                label6.Text = label6.Text + "Presented device is not a Vivokey device.";
            }
            
        }

        private void readersComboBox_SelectedIndexChanged(object sender, EventArgs e)
        {
            monitor.Start(readersComboBox.Text);
        }
    }
}
