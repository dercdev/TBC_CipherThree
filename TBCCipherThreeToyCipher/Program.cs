using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Interfaces;

namespace TBCCipherThreeToyCipher
{
    class Program
    {
        static void Main(string[] args)
        {
            AttackLastRound();

            Console.WriteLine("Press any key...");
            Console.ReadKey();
        }

        static void AttackLastRound()
        {
            Encryption encryption = new Encryption();
            Analysis analysis = new Analysis();

            Console.WriteLine("Current keys: " + encryption.PrintKeys());

            //analysis the sbox
            List<Differential> diffList = analysis.CountDifferentialsSingleSBox();

            bool[] attackSBox = new bool[] { true };

            //Check the attack new
            CipherThreeDifferentialKeyRecoveryAttack keyRecoveryConfiguration = new CipherThreeDifferentialKeyRecoveryAttack();

            SearchPolicy curSearchPolicy = SearchPolicy.FirstBestCharacteristicDepthSearch;
            AbortingPolicy curAbortingPolicy = AbortingPolicy.Threshold;

            //attack round 3
            DifferentialAttackRoundConfiguration configRound3SBox1 = analysis.GenerateConfigurationAttack(3, attackSBox, curAbortingPolicy, curSearchPolicy, diffList, keyRecoveryConfiguration, encryption);
            DifferentialAttackRoundResult resultRound3SBox1 = analysis.RecoverKeyInformation(keyRecoveryConfiguration, configRound3SBox1, encryption);
            keyRecoveryConfiguration.RoundConfigurations.Add(configRound3SBox1);
            keyRecoveryConfiguration.RoundResults.Add(resultRound3SBox1);

            //Result
            keyRecoveryConfiguration.Subkey3 = resultRound3SBox1.PossibleKey;
            keyRecoveryConfiguration.RecoveredSubkey3 = true;
            Console.WriteLine(keyRecoveryConfiguration.printRecoveredSubkeyBits());

           
        }
    }
}
