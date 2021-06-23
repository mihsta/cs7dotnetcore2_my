using System;
using static System.Console;
using Packt.CS7;

namespace SigningApp
{
    class Program
    {
        static void Main(string[] args)
        {
            Write("Enter some test to sign: ");
            string data = ReadLine();
            var signature = Protector.GenerateSignature(data);
            WriteLine($"Signature: {signature}");
            WriteLine("Publick key used to check signature: ");
            WriteLine(Protector.PublicKey);

            if (Protector.ValidateSignature(data, signature))
            {
                WriteLine("Correct! Signature is valid.");
            }
            else
            {
                WriteLine("Invalid signature.");
            }

            //создаем поддельную подпись, заменив первый символ на X
            var fakeSignature = signature.Replace(signature[0],'X');

            if (Protector.ValidateSignature(data, fakeSignature))
            {
                WriteLine("Correct! Signature is valid.");
            }
            else
            {
                WriteLine($"Invalid signature: {fakeSignature}");
            }

        }
    }
}
