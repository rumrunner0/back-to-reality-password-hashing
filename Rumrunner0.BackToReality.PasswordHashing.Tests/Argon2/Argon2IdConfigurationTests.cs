using Rumrunner0.BackToReality.PasswordHashing.Argon2;
using Xunit;

namespace Rumrunner0.BackToReality.PasswordHashing.Tests.Argon2;

/// <summary>Tests for <see cref="Argon2IdConfiguration" />.</summary>
public sealed class Argon2IdConfigurationTests
{
	#region Presets

	/// <summary>Ensures that the RFC 9106 presets expose the expected values.</summary>
	[Fact]
	public void Presets_ExposeExpectedValues()
	{
		Assert.Equal(2048 * 1024, Argon2IdConfiguration.FirstRecommended.Memory);
		Assert.Equal(1, Argon2IdConfiguration.FirstRecommended.Iterations);
		Assert.Equal(4, Argon2IdConfiguration.FirstRecommended.Lanes);

		Assert.Equal(64 * 1024, Argon2IdConfiguration.SecondRecommended.Memory);
		Assert.Equal(3, Argon2IdConfiguration.SecondRecommended.Iterations);
		Assert.Equal(4, Argon2IdConfiguration.SecondRecommended.Lanes);
	}

	#endregion

	#region TryParse

	/// <summary>Ensures that a valid parameter string parses to the expected configuration.</summary>
	[Fact]
	public void TryParse_ValidParameters_ReturnsConfiguration()
	{
		Assert.True(Argon2IdConfiguration.TryParse("m=65536,t=3,p=4", out var configuration));
		Assert.Equal(new Argon2IdConfiguration(Memory: 65536, Iterations: 3, Lanes: 4), configuration);
	}

	/// <summary>Ensures that boundary values within the supported bounds are accepted.</summary>
	[Fact]
	public void TryParse_BoundaryParameters_ReturnsConfiguration()
	{
		// The spec minimum: m = 8p.
		Assert.True(Argon2IdConfiguration.TryParse("m=32,t=1,p=4", out _));

		// The supported maximums.
		Assert.True(Argon2IdConfiguration.TryParse("m=8388608,t=64,p=64", out _));
	}

	/// <summary>Ensures that <c>null</c> is rejected.</summary>
	[Fact]
	public void TryParse_Null_ReturnsFalse()
	{
		Assert.False(Argon2IdConfiguration.TryParse(null, out var configuration));
		Assert.Null(configuration);
	}

	/// <summary>Ensures that a parameter string with a wrong shape is rejected.</summary>
	[Fact]
	public void TryParse_MalformedParameters_ReturnsFalse()
	{
		Assert.False(Argon2IdConfiguration.TryParse("", out _));
		Assert.False(Argon2IdConfiguration.TryParse("m=65536", out _));
		Assert.False(Argon2IdConfiguration.TryParse("m=65536,t=3", out _));
		Assert.False(Argon2IdConfiguration.TryParse("m=65536,t=3,p=4,x=1", out _));
		Assert.False(Argon2IdConfiguration.TryParse("m=65536;t=3;p=4", out _));

		// The parameter order is fixed by the PHC spec.
		Assert.False(Argon2IdConfiguration.TryParse("t=3,m=65536,p=4", out _));
	}

	/// <summary>Ensures that a parameter value that is not a plain ASCII number is rejected.</summary>
	[Fact]
	public void TryParse_NonCanonicalIntegers_ReturnsFalse()
	{
		Assert.False(Argon2IdConfiguration.TryParse("m=+65536,t=3,p=4", out _));
		Assert.False(Argon2IdConfiguration.TryParse("m= 65536,t=3,p=4", out _));
		Assert.False(Argon2IdConfiguration.TryParse("m=65536,t=3.0,p=4", out _));
		Assert.False(Argon2IdConfiguration.TryParse("m=65536,t=3,p=", out _));
	}

	/// <summary>Ensures that parameters outside the supported bounds are rejected.</summary>
	[Fact]
	public void TryParse_OutOfBoundsParameters_ReturnsFalse()
	{
		// Iterations and lanes outside [1, 64].
		Assert.False(Argon2IdConfiguration.TryParse("m=65536,t=0,p=4", out _));
		Assert.False(Argon2IdConfiguration.TryParse("m=65536,t=65,p=4", out _));
		Assert.False(Argon2IdConfiguration.TryParse("m=65536,t=3,p=0", out _));
		Assert.False(Argon2IdConfiguration.TryParse("m=65536,t=3,p=65", out _));

		// Memory below the spec minimum of 8 KiB per lane and above the supported maximum.
		Assert.False(Argon2IdConfiguration.TryParse("m=24,t=1,p=4", out _));
		Assert.False(Argon2IdConfiguration.TryParse("m=8388609,t=3,p=4", out _));
		Assert.False(Argon2IdConfiguration.TryParse("m=2147483647,t=3,p=4", out _));
	}

	#endregion
}
