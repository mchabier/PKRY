using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Klient
{
    class Protokol
    {
        public static string PURCHASE_INIT = "#Inicjuj_Zakupy";
        public static string PURCHASE_INIT_RES = "#Inicjuj_Zakupy_Odpowiedz";
        public static string PURCHASE_REQ = "#Zapytanie_Zakupy";
        public static string PURCHASE_REQ_RES = "#Zapytanie_Zakupy_Odpowiedz";
        public static string BLAD = "#Błąd_w_Komunikacji";
        public static string AUTHORIZATION_REQ = "#Zapytanie_o_Autoryzację";
        public static string AUTHORIZATION_RES = "#Odpowiedz_o_Autoryzację";
        public static string PAYMENT_REQ = "#Zapytanie_o_Platnosc";
        public static string PAYMENT_RES = "#Odpowiedz_o_Platnosc";
    }
}
