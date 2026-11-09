using NUnit.Framework;

namespace Lab1.Tests;

[TestFixture]
public class BitPermutationTests
{
    [Test]
    public void Permute_MostToLeastSignificant_IdentityPermutationKeepsValue()
    {
        byte[] value = { 0xB2, 0x65 };
        int[] identity = Enumerable.Range(1, 16).ToArray();

        byte[] result = BitPermutation.Permute(
            value,
            identity,
            BitIndexDirection.MostToLeastSignificant,
            BitIndexBase.One);

        Assert.That(result, Is.EqualTo(value));
    }

    [Test]
    public void Permute_LeastToMostSignificant_IdentityPermutationKeepsValue()
    {
        byte[] value = { 0xB2, 0x65 };
        int[] identity = Enumerable.Range(0, 16).ToArray();

        byte[] result = BitPermutation.Permute(
            value,
            identity,
            BitIndexDirection.LeastToMostSignificant,
            BitIndexBase.Zero);

        Assert.That(result, Is.EqualTo(value));
    }

    [Test]
    public void Permute_MostToLeastSignificant_ReversesBitsInsideByte()
    {
        byte[] value = { 0b1101_0010 };
        int[] reversed = { 8, 7, 6, 5, 4, 3, 2, 1 };

        byte[] result = BitPermutation.Permute(
            value,
            reversed,
            BitIndexDirection.MostToLeastSignificant,
            BitIndexBase.One);

        Assert.That(result, Is.EqualTo(new byte[] { 0b0100_1011 }));
    }

    [Test]
    public void Permute_MostToLeastSignificant_SelectsBitsAcrossByteBoundary()
    {
        byte[] value = { 0xB2, 0x65 };
        int[] permutation = { 16, 1, 10, 7, 4, 13, 8, 11 };

        byte[] result = BitPermutation.Permute(
            value,
            permutation,
            BitIndexDirection.MostToLeastSignificant,
            BitIndexBase.One);

        Assert.That(result, Is.EqualTo(new byte[] { 0xF9 }));
    }

    [TestCase(BitIndexDirection.MostToLeastSignificant, 0x90)]
    [TestCase(BitIndexDirection.LeastToMostSignificant, 0x02)]
    public void Permute_DirectionControlsIndexingAndOutputBitOrder(
        BitIndexDirection direction,
        byte expected)
    {
        byte[] value = { 0b1001_0010 };
        int[] firstFourBits = { 0, 1, 2, 3 };

        byte[] result = BitPermutation.Permute(
            value,
            firstFourBits,
            direction,
            BitIndexBase.Zero);

        Assert.That(result, Is.EqualTo(new[] { expected }));
    }

    [Test]
    public void Permute_WhenOutputIsNotWholeByte_LeavesUnusedBitsZero()
    {
        byte[] value = { 0b1010_0000 };
        int[] firstThreeBits = { 1, 2, 3 };

        byte[] result = BitPermutation.Permute(
            value,
            firstThreeBits,
            BitIndexDirection.MostToLeastSignificant,
            BitIndexBase.One);

        Assert.That(result, Is.EqualTo(new byte[] { 0b1010_0000 }));
    }

    [Test]
    public void Permute_AllowsRepeatedIndexes()
    {
        byte[] value = { 0b1010_0000 };
        int[] permutation = { 1, 1, 1, 2, 2, 2, 3, 3 };

        byte[] result = BitPermutation.Permute(
            value,
            permutation,
            BitIndexDirection.MostToLeastSignificant,
            BitIndexBase.One);

        Assert.That(result, Is.EqualTo(new byte[] { 0b1110_0011 }));
    }

    [Test]
    public void Permute_EmptyPermutationReturnsEmptyArray()
    {
        byte[] result = BitPermutation.Permute(
            Array.Empty<byte>(),
            Array.Empty<int>(),
            BitIndexDirection.MostToLeastSignificant,
            BitIndexBase.One);

        Assert.That(result, Is.Empty);
    }

    [Test]
    public void Permute_NullValueThrowsArgumentNullException()
    {
        ArgumentNullException exception = Assert.Throws<ArgumentNullException>(() =>
            BitPermutation.Permute(
                null!,
                new[] { 1 },
                BitIndexDirection.MostToLeastSignificant,
                BitIndexBase.One))!;

        Assert.That(exception.ParamName, Is.EqualTo("value"));
    }

    [Test]
    public void Permute_NullPermutationThrowsArgumentNullException()
    {
        ArgumentNullException exception = Assert.Throws<ArgumentNullException>(() =>
            BitPermutation.Permute(
                new byte[] { 0 },
                null!,
                BitIndexDirection.MostToLeastSignificant,
                BitIndexBase.One))!;

        Assert.That(exception.ParamName, Is.EqualTo("pBlock"));
    }

    [TestCase(BitIndexBase.Zero, -1)]
    [TestCase(BitIndexBase.Zero, 8)]
    [TestCase(BitIndexBase.One, 0)]
    [TestCase(BitIndexBase.One, 9)]
    public void Permute_IndexOutsideInputThrowsArgumentOutOfRangeException(
        BitIndexBase indexBase,
        int invalidIndex)
    {
        ArgumentOutOfRangeException exception = Assert.Throws<ArgumentOutOfRangeException>(() =>
            BitPermutation.Permute(
                new byte[] { 0 },
                new[] { invalidIndex },
                BitIndexDirection.MostToLeastSignificant,
                indexBase))!;

        Assert.That(exception.ParamName, Is.EqualTo("pBlock"));
    }
}
