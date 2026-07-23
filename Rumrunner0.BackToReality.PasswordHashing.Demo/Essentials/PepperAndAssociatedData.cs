using System;
using Rumrunner0.BackToReality.PasswordHashing.Argon2;

namespace Rumrunner0.BackToReality.PasswordHashing.Demo.Essentials;

/// <summary>Pepper and associated data (binding a hash to a secret and a context).</summary>
internal static class PepperAndAssociatedData
{
	/// <summary>Runs the example.</summary>
	internal static void Run()
	{
		// A pepper is an application-wide secret stored outside the database;
		// associated data binds the hash to a context, e.g. a user id.
		var hash = Argon2IdPasswordHasher.Hash("p@ssw0rd", pepper: "app-secret", associatedData: "user-42");

		// Verification succeeds only when both values match the ones used during hashing.
		Console.WriteLine($"all match:      {Argon2IdPasswordHasher.Verify("p@ssw0rd", hash, pepper: "app-secret", associatedData: "user-42")}");
		Console.WriteLine($"missing pepper: {Argon2IdPasswordHasher.Verify("p@ssw0rd", hash, associatedData: "user-42")}");
		Console.WriteLine($"another user:   {Argon2IdPasswordHasher.Verify("p@ssw0rd", hash, pepper: "app-secret", associatedData: "user-1")}");
	}
}
