# ShuffleCrypt
Test of An Experimental Minimalistic Cryptographic Algorithm

ShuffleCrypt is an attempt to design a minimalistic hand-operated cryptographic algorithm which is resillient against known plaintext attacks.  The core cryptographic primitive is dynamic substitution (substitution cipher wherein the substitution gets permuted as the cipher is operated).  The operations used by the algorithm are:  Modular addition, value comparison, search for a symbol, and transfer a symbol.  Thse operations as well as the low amount of complexity are intended to make the algorithm suitable for hand operation with a deck of cards or with sliding tiles.

The cipher uses a permutation of an alphabet as its internal state.  The initial permutation is the key.  A random initialization vector is needed to put the cipher into a globally unique state.  Single-symbol encryption is defined as finding the plaintext symbol in the cipher state and writing the next symbol into the ciphertext.  Single symbol decryption is defined as finding the ciphertext symbol in the cipher state and writing the preceding symbol into the plaintext.  After every operation (for both encryption and decryption), the cipher state is permuted by what this project will refer to as a series of "metacipher" operations. 

A metacipher uses a portion of the internal state to deterministically move a symbol to another location in the cipher state.  This manipulation is intended to be easily computable with full knowledge of the internal state of the cipher and an intractible problem when the only knowledge has to comes from known plaintexts.

The metacipher operation (performed on a metacipher operand) uses convolutions of the cipher state to select a target symbol and an offset, then finds the target symbol, then moves the operand symbol to the specified offset [in relation to that target symbol].  One such operation is applied to each symbol to move, and the metacipher for each symbol should use a different subset of the state.  The most important symbols to move with a metacipher are the plaintext and ciphertext symbols.

More specifically, a metacipher defines a set of symbols in the cipher state at specified offsets from the metacipher operand (symbol to reposition in the cipher state).  The values of the symbols at each offset are summed, and reduced [modulo the cipher state length], yielding the metacipher output.  In simple formulation of the cipher, all symbols referenced by the metacipher are compared with immediately preceding symbols [in cipher state] to generate a binary value to use as an offset (for each corresponding offset, set a bit value of 1 if SymbolValue > PrecedingSymbolValue, otherwise 0).  In the more complex (presumably more secure, but more difficult to hand-operate) formulation, a separate metacipher is evaluated to generate that offset [so that any involved symbol can maximally and almost-uniformly influence the outcome].


The security of this cipher under a known plaintext attack depends on the cipher state at any given point of attack (any plaintext/ciphertext symbol pair) being virtually unpredicable without broad knowledge of the cipher state.  At any given point, two symbols may be known with certainty.  A few additional symbol pairs may be assumed by looking at the next few ciphertext/plaintext symbol-pairs (though the certainty about this rapidly diminishes).  No information about the order of these symbol pairs or distance between them in the cipher-state is provided (and care has been taken to keep this concealed).   It is intended that a metacipher be guessed accurately in order to meaningfully determine its effect on the state and that the state be guessed accurately in order to determine whether or not a guess about the metacipher is accurate.  It is also intended that even with fairly simple settings, a guess about the cipher state which is off by a few symbols should be indistinguishable from a guess which is contrived to match a few symbols of a plaintext/ciphertext message pair.  And, such a contrived guess about the cipher state should not be significantly better than a random guess.

Ideally it should only be required that two symbols be moved for each symbol encrypted (namely, the plaintext and ciphertext symbols).  A minimal metacipher size preference has not yet been determined.  Ideally, the cipher should only require one round per symbol to secure a message.  These ideals are the standards used for reasoning about the cipher's security and useability, not the standards that should be employed in the event that the cipher gets seriously considered for actual use (after which, more rounds, more symbols, larger metaciphers [though not too large], rounds with state-tables which are distinct from each other, and other tweaks would be made as needed).


Known defects:
When encrypting long repeating sequences of symbols, the cipher tends to start repeating its state, yielding a patterned ciphertext.  This is not presently considered a problem for hand-operation, and it can easily be corrected.


Disclaimer:  As far as ciphers go, this one is an oddball, and apart from a serious cryptanalisys and study into parameter selection and operational requirements, it should not be used for anything serious.  It should at least be an interesting puzzle.

This project contains a single python script with a test implementation of the core algorithm.  The script is for use with a Python interactive shell.  

  BASIC USAGE:
  from shufflecrypt import SCCipher
  cipher = SCCipher()
  cipher.setKey("secret")
  cipher.encrypt("the quick brown fox jumps over the lazy dog.")
  cipher.decrypt("aic ufjdl thttp blt avurb sitx auc qgmi qtm.")

  cipher.opmode:
  To control what happens in encrypt() and decrypt(), set cipher.opmode to one of the following:
    SCCipher.OPMODE_CONTINUOUS           # do nothing special, retain state
    SCCipher.OPMODE_SINGLE               # reset before encrypting or decrypting and don't set an IV
    SCCipher.OPMODE_SINGLE_WITHIV        # reset and apply the most recent IV before encrypting or decrypting (random IV if none).
    SCCipher.OPMODE_SINGLE_WITHRANDIV    # reset and apply a random IV before encrypting or decrypting.

  FEEDBACK SETTINGS:
  cipher.printIVs                        # if True, applyIV() also prints the IV to the console
  cipher.printState                      # if True, cipher state is printed to the console before and after encrypting/decrypting
  cipher.printMessages                   # if True, encrypt() and decrypt() print transformed messages to the console
  cipher.returnMessages                  # if True, encrypt() and decrypt() return the transformed message
      
  FORMATTING: 
    SCCipher.FORMAT_TEXT                 # text-based data representation
    SCCipher.FORMAT_LIST                 # integer-based data representation
  self.printformat                       # format to use when printing to console
  self.outputformat                      # format to use if/when encrypt() and decrypt() return
  
  METACIPHER SETTINGS:
  
  cipher.defineMetacipher()              # Define a metacipher
  cipher.removeMetacipher()              # Delete a metacipher
  cipher.defineOffsetMetacipher()        # Define an offset metacipher (for use with DI
  cipher.removeOffsetMetacipher()        # Delete a single metacipher
  
  RANDOM METACIPHER GENERATORS:
  cipher.random2Symbol()                 # Set up a pair of random metaciphers with relatively modest parameterization (something like the envisioned setup)
  cipher.randomCrazy()                   # Set up a quintet of much more random metaciphers
  
  
  MetaCipher operand displacement modes (SCCipher.mc_dispmode)  (the mechanism that conceals metacipher sums)
    DISPMODE_TRUNCATED_BINARY=0   # operand displacement:  mc_dispconst + (displacement & mc_dispmask)
    DISPMODE_BINARY=1             # operand displacement:  mc_dispconst + displacement
    DISPMODE_CONSTANT=2           # operand displacement:  mc_dispconst
    DISPMODE_SEPMC=3              # operand displacement:  compute other metaciphers to generate a displacement value
  
  
