using System;
using Rumrunner0.BackToReality.PasswordHashing.Argon2;

namespace Rumrunner0.BackToReality.PasswordHashing.Demo.Essentials;

/// <summary>Anatomy of a hash (the PHC string format piece by piece).</summary>
internal static class AnatomyOfAHash
{
	/// <summary>Runs the example.</summary>
	internal static void Run()
	{
		var hash = Argon2IdPasswordHasher.Hash("p@ssw0rd");
		var parts = hash.Split('$');

		Console.WriteLine(hash);
		Console.WriteLine($"algorithm:  {parts[1]}");
		Console.WriteLine($"version:    {parts[2]}");
		Console.WriteLine($"parameters: {parts[3]} (m = memory in KiB, t = iterations, p = lanes)");
		Console.WriteLine($"salt:       {parts[4]} (Base64, no padding)");
		Console.WriteLine($"tag:        {parts[5]} (Base64, no padding)");
	}
}
