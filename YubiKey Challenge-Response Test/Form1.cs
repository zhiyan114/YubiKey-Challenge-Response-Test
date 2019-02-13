using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using YubiClientAPILib;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.IO;
using System.Security.Cryptography;
using System.Diagnostics;
using Microsoft.Win32;
using System.Security.Principal;

namespace YubiKey_Challenge_Response_Test
{
    public partial class Form1 : Form
    {
        private static int DEFAULT_ITERATIONS = 10000;
        YubiClient api;
        public Form1()
        {
            InitializeComponent();
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            Write("Software Loaded");
            if (IsAdministrator())
            {
                Text = "Administrator: " + Text;
                Write("The Software is ran as administrator, please do not run it as administrator unless you are installing the main component for safety issues.");
            }
                

            //{921F5C8E-A7AC-4649-9CDC-4D9CDB1B35C5}
            if(!COMRegistered("{921F5C8E-A7AC-4649-9CDC-4D9CDB1B35C5}"))
            {
                TopMost = true;
                DialogResult confirmation = MessageBox.Show(this,"The Main Component is not installed, would you like to install it? (Required administrator privilege)","COM Not Detected",MessageBoxButtons.YesNoCancel,MessageBoxIcon.Information);
                TopMost = false;
                if (confirmation == DialogResult.Yes)
                {
                    if(IsAdministrator())
                    {
                        // Install it
                    } else
                    {
                        MessageBox.Show("The main component cannot be installed due to lack of privilege, please run this software as administrator and try again (after you installed, administrator is not required). Press ok and the software will exit", "Installation Failed",MessageBoxButtons.OK,MessageBoxIcon.Error);
                    }
                } else if(confirmation == DialogResult.No)
                {
                    MessageBox.Show("The Main Component cannot be detected from the registery. If you have choose to continue without installing so unless your sure that it installed and the detection made a mistake then an error will be thrown when you press OK","Main Component Not Detected",MessageBoxButtons.OK,MessageBoxIcon.Warning);
                } else if(confirmation == DialogResult.Cancel)
                {
                    MessageBox.Show("You have selected to quit the software, press ok to exit","Software Exit",MessageBoxButtons.OK,MessageBoxIcon.Information);
                    Close();
                    return;
                } else
                {
                    MessageBox.Show("The Response was returned incorrectly, software will now shutdown","Unknown Error",MessageBoxButtons.OK,MessageBoxIcon.Error);
                    Close();
                    return;
                }
            }
            try
            {
                api = new YubiClient();
            } catch(Exception ex)
            {
                MessageBox.Show("Software cannot start up, press ok to shutdown the software. Error: \n"+ex.Message,"Software Startup Error",MessageBoxButtons.OK,MessageBoxIcon.Error);
                Close();
                return;
            }
            api.enableNotifications = ycNOTIFICATION_MODE.ycNOTIFICATION_ON;
            if (string.IsNullOrWhiteSpace(Properties.Settings.Default.Challenge))
            {
                button2.Enabled = false;
                Write("You did not configurate the challenge yet, please configurate it before testing it out");
            }
        }

        private void button3_Click(object sender, EventArgs e)
        {
            File.WriteAllText("Exported.log.txt",textBox1.Text);
            Write("Log Exported");
            MessageBox.Show("All the logs as now been exported","Export Completed",MessageBoxButtons.OK,MessageBoxIcon.Information);
        }
        private void Write(string content)
        {
            textBox1.Text = textBox1.Text + DateTime.Now.ToString("MM/dd/yyyy hh:mm tt") + ": " + content + "\r\n";
        }

        private void button2_Click(object sender, EventArgs e)
        {
            Stopwatch sw = new Stopwatch();
            sw.Start();
            byte[] challenge = Convert.FromBase64String(Properties.Settings.Default.Challenge);
            byte[] salt = Convert.FromBase64String(Properties.Settings.Default.Salt);
            byte[] response = DoChallengeResponse(challenge, salt);
            if (response == null)
            {
                sw.Stop();
                Write("Challenge Response Failed");
                return;
            }
            byte[] correctResponse = Convert.FromBase64String(Properties.Settings.Default.Response);
            if (Enumerable.SequenceEqual(response, correctResponse))
            {
                if (ConfigureNewChallengeAndResponse(salt))
                {
                    sw.Stop();
                    Write("Correct Response, test success and tooked "+sw.ElapsedMilliseconds+"ms");
                }
                else
                {
                    sw.Stop();
                    Write("test success but bad response and tooked " + sw.ElapsedMilliseconds + "ms");
                }
            }
            else
            {
                sw.Stop();
                Write("Incorrect Response was supplied");
            }
        }

        private void button1_Click(object sender, EventArgs e)
        {
            Stopwatch sw = new Stopwatch();
            sw.Start();
            if(ConfigureNewChallengeAndResponse(ConfigureNewSalt()))
            {
                sw.Stop();
                Write("Configurating Challenge success and tooked "+ sw.ElapsedMilliseconds + "ms");
                button2.Enabled = true;
            } else
            {
                sw.Stop();
                Write("Configurating Challenge failed");
            }
            Properties.Settings.Default.Save();
        }
        public static bool IsAdministrator()
        {
            var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
        private bool COMRegistered(string clsid)
        {
            using (var classesRootKey = Microsoft.Win32.RegistryKey.OpenBaseKey(
                   Microsoft.Win32.RegistryHive.ClassesRoot, Microsoft.Win32.RegistryView.Default))
            {

                var clsIdKey = classesRootKey.OpenSubKey(@"Wow6432Node\CLSID\" + clsid) ??
                                classesRootKey.OpenSubKey(@"CLSID\" + clsid);

                if (clsIdKey != null)
                {
                    clsIdKey.Dispose();
                    return true;
                }

                return false;
            }
        }
        private bool ConfigureNewChallengeAndResponse(byte[] salt)
        {
            RNGCryptoServiceProvider random = new RNGCryptoServiceProvider();
            byte[] challenge = new byte[63];
            random.GetBytes(challenge);
            //Encoding.UTF8.GetBytes(username);
            byte[] response = DoChallengeResponse(challenge, salt);
            if (response != null)
            {
                Properties.Settings.Default.Challenge = Convert.ToBase64String(challenge.ToArray<byte>());
                Properties.Settings.Default.Response = Convert.ToBase64String(response);
                return true;
            }
            return false;
        }

        private byte[] ConfigureNewSalt()
        {
            RNGCryptoServiceProvider random = new RNGCryptoServiceProvider();
            byte[] salt = new byte[63];
            random.GetBytes(salt);
            Properties.Settings.Default.Salt = Convert.ToBase64String(salt.ToArray<byte>());
            return salt;
        }

        private byte[] DoChallengeResponse(byte[] challenge, byte[] salt)
        {
            String chal = BitConverter.ToString(challenge);
            chal.Replace("-", "");
            byte[] res = null;
            api.dataEncoding = ycENCODING.ycENCODING_BYTE_ARRAY;
            api.dataBuffer = chal;
            ycRETCODE ret = api.get_hmacSha1(2, ycCALL_MODE.ycCALL_BLOCKING);
            if (ret == ycRETCODE.ycRETCODE_OK)
            {
                Stopwatch sw = Stopwatch.StartNew();
                int iterations = DEFAULT_ITERATIONS;
                object iterationsObj = DEFAULT_ITERATIONS;
                if (iterationsObj != null)
                {
                    iterations = (int)iterationsObj;
                }
                byte[] response = api.dataBuffer;
                Rfc2898DeriveBytes pbkdf2 = new Rfc2898DeriveBytes(response, salt, iterations);
                res = pbkdf2.GetBytes(128);
                sw.Stop();
                //testOutputLabel.Text = "Result hashing took " + sw.ElapsedMilliseconds / 1000.0 + " seconds.";
            }
            return res;
        }
    }
}
