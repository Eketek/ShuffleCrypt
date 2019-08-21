# ShuffleCrypt
Test of An Experimental Minimalistic Cryptographic Algorithm

ShuffleCrypt is an attempt to design a minimalistic hand-operated cryptographic algorithm which is resillient against known plaintext attacks.  The core cryptographic primitive is dynamic substitution (substitution cipher wherein the substitution gets permuted as the cipher is operated).  The operations used by the algorithm are:  Modular addition, value comparison, search for a symbol, and transfer a symbol.  Thse operations as well as the low amount of complexity are intended to make the algorithm suitable for hand operation with a deck of cards or with sliding tiles.

The cipher uses a permutation of an alphabet as its internal state.  The initial permutation is the key.  A random initialization vector is needed to put the cipher into a globally unique state.  Single-symbol encryption is defined as finding the plaintext symbol in the cipher state and writing the next symbol into the ciphertext.  Single symbol decryption is defined as finding the ciphertext symbol in the cipher state and writing the preceding symbol into the plaintext.  After every operation (for both encryption and decryption), the cipher state is permuted by what this project will refer to as a series of "metacipher" operations.  There are no limitations on how 

A metacipher uses a portion of the internal state to deterministically move a symbol to another location in the cipher state.  This manipulation is intended to be easily computable with full knowledge of the internal state of the cipher and an intractible problem when the only knowledge has to comes from known plaintexts.

The metacipher operation (performed on a metacipher operand) uses differing mathematical operations on a subset of the cipher state (a series of offsets from the symbol to move) to select a target symbol and an offset, then finds the target symbol, then moves the operand symbol to the specified offset [in relation to that target symbol].  One such operation is applied to each symbol to move, and the metacipher for each symbol should use a different subset of the state.  The most important symbols to move with a metacipher are the plaintext and ciphertext symbols.

Disclaimer:  As far as ciphers go, this one is an oddball, and apart from a serious cryptanalisys and study into parameter selection and operational requirements, it should not be used for anything serious.  It should at least be an interesting puzzle.


This project contains a single python script witha  test implementation of the core algorithm.  The script is for use with a Python interactive shell.  

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
  cipher.defineMetacipher()              # Define a single metacipher
  cipher.removeMetacipher()              # Delete a single metacipher
  
  RANDOM METACIPHER GENERATORS:
  cipher.random2Symbol()                 # Set up a pair of random metaciphers with relatively modest parameterization (something like the envisioned setup)
  cipher.randomCrazy()                   # Set up a quintet of much more random metaciphers
  