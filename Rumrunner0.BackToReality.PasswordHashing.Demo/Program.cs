using System;
using Rumrunner0.BackToReality.PasswordHashing.Demo.Essentials;

Console.WriteLine("Rumrunner0.BackToReality.PasswordHashing Guide");

Run("Essentials 1. Hashing and verification", HashingAndVerification.Run);
Run("Essentials 2. Anatomy of a hash", AnatomyOfAHash.Run);
Run("Essentials 3. Pepper and associated data", PepperAndAssociatedData.Run);
Run("Essentials 4. Configurations", Configurations.Run);
Run("Essentials 5. Hostile and malformed hashes", HostileAndMalformedHashes.Run);

return;

static void Run(string title, Action example)
{
	Console.WriteLine();
	Console.WriteLine($"--- {title} ---");
	Console.WriteLine();
	example();
}
