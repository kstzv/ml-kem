// SPDX-License-Identifier: GPL-2.0 OR MIT
// Copyright (c) 2026 K.S.Zavertailo

// Optimized Keccak-f[1600] permutation for ML-KEM.
// Drop-in replacement for the old table/index based keccak_f1600_ct().
// API is unchanged: SHAKE/SHA3 wrappers can keep calling keccak_f1600_ct(u64 state[25]).
//
// Core structure follows the well-known unrolled Keccak-f1600 layout used by
// compact/high-speed FIPS202 implementations: 25 lanes are kept as local
// variables and two rounds are processed per loop iteration.

#include "ml_kem_core_header.h"

#define KECCAKF_ROUNDS 24
#define ROL64(a, offset) (((a) << (offset)) | ((a) >> (64 - (offset))))

// Forward declaration kept for consistency with the original file.
void keccak_f1600_ct(u64 state[25]);

/* Keccak round constants */
static const u64 keccakf_rndc[KECCAKF_ROUNDS] = {
    0x0000000000000001ULL, 0x0000000000008082ULL,
    0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL,
    0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL,
    0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL,
    0x0000000080000001ULL, 0x8000000080008008ULL
};

/*************************************************
 * Name:        keccak_f1600_ct
 *
 * Description: The Keccak F1600 Permutation
 *
 * Arguments:   - u64 *state: pointer to input/output Keccak state
 **************************************************/
void keccak_f1600_ct(u64 state[25])
{
    int round;

    u64 Aba, Abe, Abi, Abo, Abu;
    u64 Aga, Age, Agi, Ago, Agu;
    u64 Aka, Ake, Aki, Ako, Aku;
    u64 Ama, Ame, Ami, Amo, Amu;
    u64 Asa, Ase, Asi, Aso, Asu;
    u64 BCa, BCe, BCi, BCo, BCu;
    u64 Da, De, Di, Do, Du;
    u64 Eba, Ebe, Ebi, Ebo, Ebu;
    u64 Ega, Ege, Egi, Ego, Egu;
    u64 Eka, Eke, Eki, Eko, Eku;
    u64 Ema, Eme, Emi, Emo, Emu;
    u64 Esa, Ese, Esi, Eso, Esu;

    // copyFromState(A, state)
    Aba = state[0];
    Abe = state[1];
    Abi = state[2];
    Abo = state[3];
    Abu = state[4];
    Aga = state[5];
    Age = state[6];
    Agi = state[7];
    Ago = state[8];
    Agu = state[9];
    Aka = state[10];
    Ake = state[11];
    Aki = state[12];
    Ako = state[13];
    Aku = state[14];
    Ama = state[15];
    Ame = state[16];
    Ami = state[17];
    Amo = state[18];
    Amu = state[19];
    Asa = state[20];
    Ase = state[21];
    Asi = state[22];
    Aso = state[23];
    Asu = state[24];

    for (round = 0; round < KECCAKF_ROUNDS; round += 2) {
        //    prepareTheta
        BCa = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
        BCe = Abe ^ Age ^ Ake ^ Ame ^ Ase;
        BCi = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
        BCo = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
        BCu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;

        // thetaRhoPiChiIotaPrepareTheta(round  , A, E)
        Da = BCu ^ ROL64(BCe, 1);
        De = BCa ^ ROL64(BCi, 1);
        Di = BCe ^ ROL64(BCo, 1);
        Do = BCi ^ ROL64(BCu, 1);
        Du = BCo ^ ROL64(BCa, 1);

        Aba ^= Da;
        BCa = Aba;
        Age ^= De;
        BCe = ROL64(Age, 44);
        Aki ^= Di;
        BCi = ROL64(Aki, 43);
        Amo ^= Do;
        BCo = ROL64(Amo, 21);
        Asu ^= Du;
        BCu = ROL64(Asu, 14);
        Eba = BCa ^ ((~BCe) & BCi);
        Eba ^= keccakf_rndc[round];
        Ebe = BCe ^ ((~BCi) & BCo);
        Ebi = BCi ^ ((~BCo) & BCu);
        Ebo = BCo ^ ((~BCu) & BCa);
        Ebu = BCu ^ ((~BCa) & BCe);

        Abo ^= Do;
        BCa = ROL64(Abo, 28);
        Agu ^= Du;
        BCe = ROL64(Agu, 20);
        Aka ^= Da;
        BCi = ROL64(Aka, 3);
        Ame ^= De;
        BCo = ROL64(Ame, 45);
        Asi ^= Di;
        BCu = ROL64(Asi, 61);
        Ega = BCa ^ ((~BCe) & BCi);
        Ege = BCe ^ ((~BCi) & BCo);
        Egi = BCi ^ ((~BCo) & BCu);
        Ego = BCo ^ ((~BCu) & BCa);
        Egu = BCu ^ ((~BCa) & BCe);

        Abe ^= De;
        BCa = ROL64(Abe, 1);
        Agi ^= Di;
        BCe = ROL64(Agi, 6);
        Ako ^= Do;
        BCi = ROL64(Ako, 25);
        Amu ^= Du;
        BCo = ROL64(Amu, 8);
        Asa ^= Da;
        BCu = ROL64(Asa, 18);
        Eka = BCa ^ ((~BCe) & BCi);
        Eke = BCe ^ ((~BCi) & BCo);
        Eki = BCi ^ ((~BCo) & BCu);
        Eko = BCo ^ ((~BCu) & BCa);
        Eku = BCu ^ ((~BCa) & BCe);

        Abu ^= Du;
        BCa = ROL64(Abu, 27);
        Aga ^= Da;
        BCe = ROL64(Aga, 36);
        Ake ^= De;
        BCi = ROL64(Ake, 10);
        Ami ^= Di;
        BCo = ROL64(Ami, 15);
        Aso ^= Do;
        BCu = ROL64(Aso, 56);
        Ema = BCa ^ ((~BCe) & BCi);
        Eme = BCe ^ ((~BCi) & BCo);
        Emi = BCi ^ ((~BCo) & BCu);
        Emo = BCo ^ ((~BCu) & BCa);
        Emu = BCu ^ ((~BCa) & BCe);

        Abi ^= Di;
        BCa = ROL64(Abi, 62);
        Ago ^= Do;
        BCe = ROL64(Ago, 55);
        Aku ^= Du;
        BCi = ROL64(Aku, 39);
        Ama ^= Da;
        BCo = ROL64(Ama, 41);
        Ase ^= De;
        BCu = ROL64(Ase, 2);
        Esa = BCa ^ ((~BCe) & BCi);
        Ese = BCe ^ ((~BCi) & BCo);
        Esi = BCi ^ ((~BCo) & BCu);
        Eso = BCo ^ ((~BCu) & BCa);
        Esu = BCu ^ ((~BCa) & BCe);

        //    prepareTheta
        BCa = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
        BCe = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
        BCi = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
        BCo = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
        BCu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;

        // thetaRhoPiChiIotaPrepareTheta(round+1, E, A)
        Da = BCu ^ ROL64(BCe, 1);
        De = BCa ^ ROL64(BCi, 1);
        Di = BCe ^ ROL64(BCo, 1);
        Do = BCi ^ ROL64(BCu, 1);
        Du = BCo ^ ROL64(BCa, 1);

        Eba ^= Da;
        BCa = Eba;
        Ege ^= De;
        BCe = ROL64(Ege, 44);
        Eki ^= Di;
        BCi = ROL64(Eki, 43);
        Emo ^= Do;
        BCo = ROL64(Emo, 21);
        Esu ^= Du;
        BCu = ROL64(Esu, 14);
        Aba = BCa ^ ((~BCe) & BCi);
        Aba ^= keccakf_rndc[round + 1];
        Abe = BCe ^ ((~BCi) & BCo);
        Abi = BCi ^ ((~BCo) & BCu);
        Abo = BCo ^ ((~BCu) & BCa);
        Abu = BCu ^ ((~BCa) & BCe);

        Ebo ^= Do;
        BCa = ROL64(Ebo, 28);
        Egu ^= Du;
        BCe = ROL64(Egu, 20);
        Eka ^= Da;
        BCi = ROL64(Eka, 3);
        Eme ^= De;
        BCo = ROL64(Eme, 45);
        Esi ^= Di;
        BCu = ROL64(Esi, 61);
        Aga = BCa ^ ((~BCe) & BCi);
        Age = BCe ^ ((~BCi) & BCo);
        Agi = BCi ^ ((~BCo) & BCu);
        Ago = BCo ^ ((~BCu) & BCa);
        Agu = BCu ^ ((~BCa) & BCe);

        Ebe ^= De;
        BCa = ROL64(Ebe, 1);
        Egi ^= Di;
        BCe = ROL64(Egi, 6);
        Eko ^= Do;
        BCi = ROL64(Eko, 25);
        Emu ^= Du;
        BCo = ROL64(Emu, 8);
        Esa ^= Da;
        BCu = ROL64(Esa, 18);
        Aka = BCa ^ ((~BCe) & BCi);
        Ake = BCe ^ ((~BCi) & BCo);
        Aki = BCi ^ ((~BCo) & BCu);
        Ako = BCo ^ ((~BCu) & BCa);
        Aku = BCu ^ ((~BCa) & BCe);

        Ebu ^= Du;
        BCa = ROL64(Ebu, 27);
        Ega ^= Da;
        BCe = ROL64(Ega, 36);
        Eke ^= De;
        BCi = ROL64(Eke, 10);
        Emi ^= Di;
        BCo = ROL64(Emi, 15);
        Eso ^= Do;
        BCu = ROL64(Eso, 56);
        Ama = BCa ^ ((~BCe) & BCi);
        Ame = BCe ^ ((~BCi) & BCo);
        Ami = BCi ^ ((~BCo) & BCu);
        Amo = BCo ^ ((~BCu) & BCa);
        Amu = BCu ^ ((~BCa) & BCe);

        Ebi ^= Di;
        BCa = ROL64(Ebi, 62);
        Ego ^= Do;
        BCe = ROL64(Ego, 55);
        Eku ^= Du;
        BCi = ROL64(Eku, 39);
        Ema ^= Da;
        BCo = ROL64(Ema, 41);
        Ese ^= De;
        BCu = ROL64(Ese, 2);
        Asa = BCa ^ ((~BCe) & BCi);
        Ase = BCe ^ ((~BCi) & BCo);
        Asi = BCi ^ ((~BCo) & BCu);
        Aso = BCo ^ ((~BCu) & BCa);
        Asu = BCu ^ ((~BCa) & BCe);
    }

    // copyToState(state, A)
    state[0] = Aba;
    state[1] = Abe;
    state[2] = Abi;
    state[3] = Abo;
    state[4] = Abu;
    state[5] = Aga;
    state[6] = Age;
    state[7] = Agi;
    state[8] = Ago;
    state[9] = Agu;
    state[10] = Aka;
    state[11] = Ake;
    state[12] = Aki;
    state[13] = Ako;
    state[14] = Aku;
    state[15] = Ama;
    state[16] = Ame;
    state[17] = Ami;
    state[18] = Amo;
    state[19] = Amu;
    state[20] = Asa;
    state[21] = Ase;
    state[22] = Asi;
    state[23] = Aso;
    state[24] = Asu;
}

#undef ROL64

