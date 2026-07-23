using System;
using Rumrunner0.BackToReality.PasswordHashing.Argon2;

namespace Rumrunner0.BackToReality.PasswordHashing.Demo.Essentials;

/// <summary>Hashing and verification (the basic round-trip).</summary>
internal static class HashingAndVerification
{
	/// <summary>Runs the example.</summary>
	internal static void Run()
	{
		// Hash produces a self-describing PHC string. Store it as-is;
		// everything needed for later verification is inside.
		var hash = Argon2IdPasswordHasher.Hash("correct horse battery staple");
		Console.WriteLine($"hash: {hash}");

		// Verify recomputes the hash from the incoming password and compares in fixed time.
		Console.WriteLine($"correct password: {Argon2IdPasswordHasher.Verify("correct horse battery staple", hash)}");
		Console.WriteLine($"wrong password:   {Argon2IdPasswordHasher.Verify("Tr0ub4dor&3", hash)}");

		// The salt is random, so the same password never produces the same hash.
		var again = Argon2IdPasswordHasher.Hash("correct horse battery staple");
		Console.WriteLine($"same password, new hash: {hash != again}");
	}
}
