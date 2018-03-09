using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

// RSA MSDN https://docs.microsoft.com/ru-ru/dotnet/standard/security/walkthrough-creating-a-cryptographic-application

namespace RSA
{
    public partial class Form1 : Form
    {
        #region Variables
        public int[] SimpleNums { get; } = {2, 3, 5, 7, 11, 13, 17, 19, 23 };
        //29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101

        private int N { get; set; }
        private int Fi_ot_N { get; set; }
        private int E { get; set; }
        private int D { get; set; }
        
        private (int, int) PQ;                  // (p, q)               // Кортежи (подключили System.ValueTuple)
        private (int, int) OpenKey;             // (E, N)
        private (int, int) SecretKey;           // (D, N)

        private string Z { get; set; }
        #endregion

        #region Find P & Q
        private void SelectPQ()
        {
            Random rnd = new Random();
            var tmp = (rnd.Next(SimpleNums.Length), rnd.Next(SimpleNums.Length));
            try
            {
                for (int i = 0; i < SimpleNums.Length; i++)
                {
                    if (SimpleNums[tmp.Item1] != SimpleNums[tmp.Item2])
                    {
                        PQ = (SimpleNums[tmp.Item1], SimpleNums[tmp.Item2]);
                    }
                    else if (tmp.Item1 != 0 & tmp.Item2 != 0) // тут была ошибка // else if (SimpleNums[tmp.Item1] != 0 & SimpleNums[tmp.Item2] != 0)
                    {
                        PQ = (SimpleNums[tmp.Item1 - 1], SimpleNums[tmp.Item2 + 1]);
                    }
                    else PQ = (SimpleNums[tmp.Item1 + 1], SimpleNums[tmp.Item2 + 2]);
                }
            }
            catch(Exception ex) { MessageBox.Show($"Возникла ошибка!\nСообщение: {ex.Message}\n" +
                                                                    $"Источник: {ex.Source}\n" +
                                                                    $"Данные: {ex.Data}"); }
        }
        #endregion

        #region Calculate_N
        private int Calculate_N((int, int) pq)
        {
            return pq.Item1  * pq.Item2;
        }
        #endregion

        #region Calculate Fi_ot_N
        private int Eiler_Func ((int, int) pq)
        {
            return (pq.Item1 - 1) * (pq.Item2 - 1);
        }
        #endregion

        #region Calculate E
        /// <summary>
        /// Метод и присваивает значение глобальной переменной "Е", 
        /// и возвращает строку - диапазон всех возможных значений "Е", из которых метод выберет одно - минимальное.
        /// Данная строка нужна исключительно для отслеживания правильности выполнения методом логики расчетов программы.
        /// Строка будет выводиться в рич-бокс
        /// </summary>
        /// <param name="n"></param>
        /// <returns></returns>
        private string Calculate_E(int n)
        {
            string s = "";
            int tmp = 0;            

            // Если N больше максимального значения в массиве простых чисел, то присвоим tmp 
            // значение индекса максимального значения массива. Если Fi_ot_N равен макс. значению массива, то 
            // присвоим tmp индекс предмаксимального значения.
            if (n == SimpleNums.Max()) tmp = SimpleNums.Length - 1;
                else if (n > SimpleNums.Max()) tmp = SimpleNums.Length;

            // Если N не равен и не больше макс. зн. массива, то сравниваем со всеми оставшимися простыми
            // числами в массиве и присваиваем tmp индекс того эл-та массива, который меньше Fi_ot_N
            for (int i = SimpleNums.Length-1; i >= 0; i--)
            {
                if (n == SimpleNums[i]) tmp = i - 1; 
                if (n <= SimpleNums[i]) tmp = i;
            }

            List<int> lst = new List<int>();
            // Сузив диапазон согласно неравенству [ 1 < е < Fi_ot_N ], можем выбрать значения, удовлетворяющие неравенству.
            // Т.о. самое минимальное из выбранных значений станет E (открытой экспонентой).
            try
            {
                for (int i = 0; i < tmp; i++)
                {   // взять E == минимальном числу, иначе будут огромные числа при возведении в степень по формуле шифрования
                    if (SimpleNums[i] % n != 0 & n % SimpleNums[i] != 0)
                    {
                        lst.Add(SimpleNums[i]);

                        s += SimpleNums[i].ToString() + ", ";
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Возникла ошибка!\nСообщение: {ex.Message}\n" +
                                                  $"Источник: {ex.Source}\n" +
                                                  $"Данные: {ex.Data}");
            }
            E = lst.Min();
            return s;
        }
        #endregion

        #region Calculate D
        // Этап расчета Д  далее остаток алгоритма
        private void Calculate_D(int e, int n)
        { // если начать от еденицы, может ли D быть == 1??
            List<int> lst = new List<int>();

            try
            {   // 400 - максимальный диапазаон, из которого выбирается число, которому будет равно "Д". Подлежит регулировке.
                for (int i = 2; i < 400; i++)
                {
                    if ((i * E) % Fi_ot_N == 1) lst.Add(i);
                }
            }
            catch (Exception ex)    // Если выскакивает данная ошибка, значит число D превышает значение в 400
            {
                MessageBox.Show($"Возникла ошибка!\nСообщение: {ex.Message}\n" +
                                                  $"Источник: {ex.Source}\n" +
                                                  $"Данные: {ex.Data}");
            }
            D = lst.Min();  // D - минимальное из возможных число
        }
        #endregion

        #region Create keys
        private void CreateKeys()
        {
            OpenKey = (E, N);
            SecretKey = (D, N);
        }
        #endregion  // Need?

        #region Text in Unicode_Value & Print
        /// <summary>
        /// Переводит полученную строку текста в массив чисел,
        /// где числа - соответствуют номерам символов в Юникоде.
        /// </summary>
        /// <param name="message"></param>
        /// <returns></returns>
        private int[] TextInUnicodeValue(string message)
        {            
            string tmp = message;            
            char[] ch_mass = new char[tmp.Length];
            ch_mass = tmp.ToCharArray();
            int[] int_mass = new int[ch_mass.Length];

            for (int i = 0; i < ch_mass.Length; i++)
            {   // Первод сивмолов в их юникод- числовое значение 
                int_mass[i] = (int)ch_mass[i];
            }
            return int_mass;
        }

        /// <summary>
        /// Перевод массива чисел в строку этих чисел для отображения
        /// </summary>
        /// <param name="M"></param>
        /// <returns></returns>
        private string Print(int[] M)
        {
            string tmp = "";
            for (int i = 0; i < M.Length; i++)
            {
                tmp += M[i].ToString() + ", ";
            }
            return tmp;
        }
        private string Print(long[] M)
        {
            string tmp = "";
            for (int i = 0; i < M.Length; i++)
            {
                tmp += M[i].ToString() + ", ";
            }
            return tmp;
        }
        #endregion

        #region Text in Unicode_Symbols + in *.txt file + in MessageBox
        /// <summary>
        /// Перевод закодированных чисел в символы Unicode
        /// </summary>
        /// <param name="M"></param>
        private void TextToUnicodeSymbols(long[] M)
        {
            string tmp = "";
            for (int i = 0; i < M.Length; i++)
            {                
                tmp += (char)M[i];
            }

            MessageBox.Show(tmp);
            textBox2.Text = tmp;

            try
            {
                using (FileStream fstream = new FileStream(Environment.GetFolderPath(Environment.SpecialFolder.Desktop) + @"1.txt", FileMode.OpenOrCreate))
                {
                    // преобразуем строку в байты
                    byte[] array = System.Text.Encoding.Default.GetBytes(tmp);
                    // запись массива байтов в файл
                    fstream.Write(array, 0, array.Length);
                    fstream.Close();
                    Process.Start(Environment.GetFolderPath(Environment.SpecialFolder.Desktop) + @"1.txt");
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"{ex.Source}, {ex.Message}");
                Application.Exit();
            }
        }
        #endregion

        #region Encode
        /// <summary>
        /// Кодирование по формуле : Шифр-текст = Исх.текст^e mod N
        ///  
        /// Mетод получает массив чисел, числа - юникод значения символов исходного текста.
        /// Возвращает массив зашифрованных значений - чисел, которые соответствуют каким-либо знакам в таблице юникод
        /// </summary>
        /// <param name="M"></param>
        /// <returns></returns>
        private long[] EncodeRSA(int[] M) 
        {
            long[] tmp = new long[M.Length];    // long : от –9 223 372 036 854 775 808 до 9 223 372 036 854 775 807 ,  занимает 8 байт.

            for (int i = 0; i < M.Length; i++)
            {                
                tmp[i] = ((long)Math.Pow((double)M[i], (double)OpenKey.Item1)) % OpenKey.Item2;     //  private (int, int) OpenKey;  => (item1, item2) =>  (E, N)
                //if (tmp[i] == 0)
                //{
                //    tmp[i] = tmp[i] + 100;
                //}
            }
            return tmp; 
        }
        #endregion

        // Правильно ли?
        #region Decode
        /// <summary>
        /// Декодирование по формуле: Исх.текст = Шифр-текст^d mod N
        /// 
        /// !!! Mетод ДОЛЖЕН получает массив чисел - юникод-кодов зашифрованных символов.
        /// Возвращает массив расшифрованных значений - чисел, которые соответствуют каким-либо знакам в таблице юникод
        /// </summary>
        /// <param name="M"></param>
        /// <returns></returns>
        private long[] DecodeRSA(int[] M)
        {
            long[] tmp = new long[M.Length];
            for (int i = 0; i < M.Length; i++)
            {
                tmp[i] = ((long)Math.Pow((double)M[i], (double)SecretKey.Item1)) % SecretKey.Item2;    //  private (int, int) SecretKey;  => (item1, item2) =>  (D, N) 
            }
            return tmp;
        }
        #endregion

        #region Show All Operations In RichTextBox
        /// <summary>
        /// Вывод информации в рич-бокс для контроля и проверки получаемых чисел и всего процесса работы рассчетной логики
        /// </summary>
        private void ShowInRTB()
        {
            richTextBox1.Text = "P = " + PQ.Item1.ToString() + "    |    Q = "
                + PQ.Item2.ToString() + "    |    N = " + N.ToString() + "    |    Fi_ot_N = " + Fi_ot_N.ToString() + "   |   Possible E Variants: [ " + Z + " ]  |    E = " + E + "    |    D = " + D + "\n\n"
                + "Числовые соответствия символов исходного текста номерам символов Unicode:\n"
                + Print(TextInUnicodeValue(textBox1.Text)) + "\n\n"
                + "Закодированные числовые соответствия символов исходного текста номерам символов Unicode:\n"
                + Print(EncodeRSA(TextInUnicodeValue(textBox1.Text))) + "\n\n";
            /*+ TextToUnicodeSymbols(EncodeRSA(TextInUnicodeValue(textBox1.Text)))*/
        }
        #endregion

        #region Main()
        public Form1()
        {
            InitializeComponent();

            textBox1.Text = "привет как дела";

            SelectPQ();

            N = Calculate_N(PQ);

            Fi_ot_N = Eiler_Func(PQ);        // вычисление Эйлеровой ф-ции

            Z = Calculate_E(Fi_ot_N);        // вычисление Е + получение всего диапазона чисел, из которого вычисляется Е

            Calculate_D(E, Fi_ot_N);         // вычисление D

            CreateKeys();                    // разнесение D, Е, N по ключам

            TextToUnicodeSymbols(EncodeRSA(TextInUnicodeValue(textBox1.Text)));     // перевод зашифрованного текста (чисел) в символы юникода - визуальное представление шифра

            ShowInRTB();                     // вывод всех значений в рич-тексбох для отслеживания
           
        }
        #endregion

        // Еще необходимо реализовать:
        // Дописать методы, вбирающие зашифрованные символы юникода, 
        // конвертирующие в их числовые значения по юникоду,
        // и передающие в метод дешифровки
        // + вывод расшифрованного (д.б. = исходному) текста в 3й текстбох
        // + физуальное оформление формы
    }
}
