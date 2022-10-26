using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;

namespace CuzdanOlusturmaAlgoritma
{
    public partial class Kullanim : System.Web.UI.Page
    {
        public static string getAdress, getPrivateKey,searchAdress;
        protected void Page_Load(object sender, EventArgs e)
        {
          
        }

        protected void btnAdresBul_Click(object sender, EventArgs e)
        {
            var privateKey = txtPrivateKey.Text.Trim();
            string address = WdrECKey.GetPublicAddress(privateKey);
            searchAdress = address;
        }

        protected void btn_Click(object sender, EventArgs e)
        {
            WdrECKey key = WdrECKey.GenerateKey();
            byte[] privateKey = key.GetPrivateKeyAsBytes();
            string address = key.GetPublicAddress();
            string hexPrivateKey = BitConverter.ToString(privateKey).Replace("-", string.Empty);
            getAdress = address;
            getPrivateKey = hexPrivateKey;
        }
    }
}