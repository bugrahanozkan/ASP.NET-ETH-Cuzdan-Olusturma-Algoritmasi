<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="Kullanim.aspx.cs" Inherits="CuzdanOlusturmaAlgoritma.Kullanim" %>

<!DOCTYPE html>

<html xmlns="http://www.w3.org/1999/xhtml">
<head runat="server">
    <title>WDR Eth Yapısında Cüzdan Oluşturma</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.1/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <form id="form1" runat="server">
                <div style="padding: 30px">
                    <div>
                        <h1>WDR Eth Yapısında Cüzdan Oluşturma</h1>
                        <hr />
                    </div>
                    <div>Adres: <%Response.Write(getAdress); %><hr />
                    </div>
                    <div>PrivateKey:  <%Response.Write(getPrivateKey); %><hr />
                    </div>
                    <asp:Button ID="btn" runat="server" Text="Yeni Oluştur" OnClick="btn_Click" />
                </div>

                <div style="padding: 30px">
                    <div>
                        <h1>PrivateKey'den Adrese Ulaşma</h1>
                        <hr />
                    </div>
                    <div>PrivateKey: 
                        <asp:TextBox ID="txtPrivateKey" Style="width: 70%" runat="server"></asp:TextBox><hr />
                    </div>
                    <div>
                        <asp:Button ID="btnAdresBul" runat="server" Text="Adresi Bul" OnClick="btnAdresBul_Click" /><hr />
                    </div>
                    <div>Bulunan Adres: <%Response.Write(searchAdress); %><hr />
                    </div>
                </div>
    </form>
</body>
</html>
