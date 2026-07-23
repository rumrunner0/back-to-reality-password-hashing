using System;
using System.Diagnostics;
using Rumrunner0.BackToReality.PasswordHashing.Argon2;

namespace Rumrunner0.BackToReality.PasswordHashing.Demo.Essentials;

/// <summary>Configurations (the RFC 9106 presets and the cost knob).</summary>
internal static class Configurations
{
	/// <summary>Runs the example.</summary>
	internal static void Run()
	{
		// Both predefined configurations come from RFC 9106.
		// The first is high-strength, the second is memory-conservative.
		Time("first recommended (2 GiB, t=1, p=4)", Argon2IdConfiguration.FirstRecommended);
		Time("second recommended (64 MiB, t=3, p=4)", Argon2IdConfiguration.SecondRecommended);

		// A custom configuration is an option too. This one is far too weak
		// for production use, but is nice and fast in tests.
		Time("custom (8 MiB, t=1, p=1)", new Argon2IdConfiguration(Memory: 8 * 1024, Iterations: 1, Lanes: 1));
	}

	/// <summary>Hashes a password using the <paramref name="configuration" /> and prints the elapsed time.</summary>
	/// <param name="title">The title to print.</param>
	/// <param name="configuration">The configuration to use.</param>
	private static void Time(string title, Argon2IdConfiguration configuration)
	{
		var stopwatch = Stopwatch.StartNew();
		Argon2IdPasswordHasher.Hash("p@ssw0rd", configuration: configuration);
		Console.WriteLine($"{title,-38} -> {stopwatch.ElapsedMilliseconds} ms");
	}
}
