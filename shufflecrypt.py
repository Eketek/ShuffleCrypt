from random import randrange, shuffle

class SCCipher:

  # operational modes.   (SCCipher.opmode)
  #  These are used to determine what an instance of SCCipher should do after encrypting or decrypting  
  OPMODE_CONTINUOUS=0           # do nothing, retain state
  OPMODE_SINGLE=1               # reset before encrypting or decrypting and don't set an IV
  OPMODE_SINGLE_WITHIV=2        # reset and apply the most recent IV before encrypting or decrypting (random IV if none).
  OPMODE_SINGLE_WITHRANDIV=3    # reset and set a random IV before encrypting or decrypting.
  
  # MetaCipher operand displacement modes (SCCipher.mc_dispmode)  (the mechanism that conceals metacipher sums)
  DISPMODE_TRUNCATED_BINARY=0   # operand displacement:  mc_dispconst + (displacement & mc_dispmask)
  DISPMODE_BINARY=1             # operand displacement:  mc_dispconst + displacement
  DISPMODE_CONSTANT=2           # operand displacement:  mc_dispconst
  DISPMODE_SEPMC=3              # operand displacement:  compute other metaciphers to generate a displacement value
  
  # Format to use for printing (SCCipher.printformat, SCCipher.outputformat) and/or for output (applied IVs, returned values from SCCipher.encrypt() and SCCipher.decrypt())
  FORMAT_TEXT=0
  FORMAT_LIST=1
  
  def __init__(self, alphabet=None, key=None):
    self.opmode = SCCipher.OPMODE_SINGLE       # see above
    self.printIVs = True                       # print IV to console when applying it
    self.printState = False                    # print state to console before and after encrypting
    self.debug = False                         # unused
    self.printMessages = True                  # print message to console after encrypting/decrypting
    self.returnMessages = False                # cause encrypt() and decrypt() to return the transformed message
    self.printformat = SCCipher.FORMAT_TEXT    # message format to use for printing to console
    self.outputformat = SCCipher.FORMAT_LIST   # message format to use if/when encrypt() and decrypt() return
    
    # initialization vector generation params
    self.iv = None        # most recently applied initialization vector
    self.ivgenlen = 16    # length of randomly generated initialization vectors

    # metacipher settings
    self.mc_dispmode = SCCipher.DISPMODE_TRUNCATED_BINARY   # see above
    self.mc_dispmask = 0xf                                  # bitmask to use for if displacement mode is truncated binary
    self.mc_dispconst = 1                                   # constant displacement parameter   
        
    #internals
    self.alphabet = alphabet
    if not alphabet:
      self.alphabet = "abcdefghijklmnopqrstuvwxyz"
    self.klen = len(self.alphabet)
    self.lexvalues = {}
    for i in range(self.klen):
      self.lexvalues[self.alphabet[i]] = i
    self.key = key
    if not key:
      self.key = self.alphabet      
    self.setKey()    
    self.metacipher = [[0, 1,2],[1, -2,-3]]  # defineMetacipher() and removeMetacipher() are preferred for editing this...
    self.offsetmetacipher = [[0,3,4], [1,-4,-5]]
        
  def clone(self):
    other = SCCipher(self.alphabet, self.key)
    other.state = list(self.state)
      
    other.opmode = self.opmode
    other.printMessages = self.printMessages
    other.printIVs = self.printIVs    
    other.printState = self.printState
    other.printformat = self.printformat
    other.outputformat = self.outputformat
    other.debug = self.debug
    other.mc_dispmode = self.mc_dispmode
    other.mc_dispmask = self.mc_dispmask
    other.mc_dispconst = self.mc_dispconst
    other.iv = self.iv
    other.ivgenlen = self.ivgenlen
    other.returnMessages = self.returnMessages
    
    other.metacipher = []
    for mc in self.metacipher:
      other.metacipher.append(list(mc))
    other.offsetmetacipher = []
    for mc in self.offsetmetacipher:
      other.offsetmetacipher.append(list(mc))
    
    return other

  def reset(self):
    self.setKey()
    
  def setKey(self, key=None):
    if not key:
      key = self.key
      
    # remove duplicate symbols from the key and spew up error messages if the key has undefined symbols
    _key = key
    key = ""
    err=False
    for ch in _key:
      if self.alphabet.find(ch) == -1:
        err=True
        print("ERROR:  undefined symbol in key: '" + ch + "'")
      if key.find(ch) == -1:
        key += ch
    if err:
      print("  key:" + key)
      print("  alphabet:  " + self.alphabet)
      
    # if the key is short, append to it all missing symbols in lexical order
    for ch in self.alphabet:
      if key.find(ch) == -1:
        key += ch
        
    self.state = []
    for i in range(self.klen):
      self.state.append(self.lexvalues[key[i]])
    self.key = key
  
    
  # generate a random IV from the builtin random library
  def genRandIV(self):
    iv = []
    for i in range(self.ivgenlen):
      iv.append(randrange(0,self.klen))
    return iv
  
  def showState(self):
    if self.printformat == SCCipher.FORMAT_TEXT:
      print("STA: " + self.toText(self.state))
    elif self.printformat == SCCipher.FORMAT_LIST:
      print("STA: " + str(self.state))
  
  def toLexvalArray(self, val):
    if isinstance(val, str):
      lval = []
      for symbol in val:
        lval.append(self.lexvalues[symbol])
      return lval
    return val
    
  def toText(self, val):
    if isinstance(val, list):
      sval = ""      
      for symbol in val:
        sval += self.alphabet[symbol]
      return sval
    return val
  
  # apply an initialization vector
  # auto-generate it if not specified
  # IV is applied by feeding it into the state transition function
  def applyIV(self, iv=None, display=True):
    if not iv:
      iv = self.genRandIV()
    if self.printIVs:
      if self.printformat == SCCipher.FORMAT_TEXT:
        print("IV : " + self.toText(iv))
      if self.printformat == SCCipher.FORMAT_LIST:
        print("IV : " + str(self.toLexvalArray(iv)))
    iv = self.toLexvalArray(iv)
    self.iv = iv
    self.digest(iv)
    
  def output(self, data, literals=None):   
    sdata = ""    
    if literals:
      _data = []
      for i in range(len(data)):  
        datan = data[i]      
        litn = literals[i]
        if litn == None:
          _data.append(datan)
          sdata += self.alphabet[datan]
        else:
          sdata += litn
      data = _data
    else:
      for datan in data:        
        sdata += self.alphabet[datan]
        
    if self.printMessages:    
      if self.printformat == SCCipher.FORMAT_TEXT:
        print("MSG: " + sdata)
      if self.printformat == SCCipher.FORMAT_LIST:
        print("MSG: " + str(data))
    if self.outputformat == SCCipher.FORMAT_TEXT:
      return sdata
    elif self.outputformat == SCCipher.FORMAT_LIST:
      return(data)
  
  def encrypt(self, pDATA):
    self.msg_init()
    if self.printState:
      self.showState()
    r = []
    literals = []
    if isinstance(pDATA, str):
      for char in pDATA:
        PTval = self.lexvalues.get(char)
        if PTval == None:
          literals.append(char)
          r.append(0)
        else:
          PTpos = self.state.index(PTval)
          literals.append(None)
          r.append(self.state[(PTpos+1)%self.klen])
          self.round(PTpos)  
    elif isinstance(pDATA, list):
      for PTval in pDATA:
        if PTval == None:
          literals.append(char)
          r.append(0)
        else:
          PTpos = self.state.index(PTval)
          literals.append(None)
          r.append(self.state[(PTpos+1)%self.klen])
          self.round(PTpos)
    cTXT = self.output(r, literals)  
    if self.printState:
      self.showState()
    if self.returnMessages:
      return cTXT
    
  def decrypt(self, cDATA):
    self.msg_init()
    if self.printState:
      self.showState()
    r = []
    literals = []
    if isinstance(cDATA, str):
      for char in cDATA:
        CTval = self.lexvalues.get(char)
        if CTval == None:
          literals.append(char)
          r.append(0)
        else:
          CTpos = self.state.index(CTval)
          PTpos = (CTpos-1) % self.klen
          literals.append(None)
          r.append(self.state[PTpos])
          self.round(PTpos)
    elif isinstance(cDATA, list):
      for CTval in cDATA:
        if CTval == None:
          literals.append(char)
          r.append(0)
        else:
          CTpos = self.state.index(CTval)
          PTpos = (CTpos-1) % self.klen
          literals.append(None)
          r.append(self.state[PTpos])
          self.round(PTpos)
    pTXT = self.output(r, literals)  
    if self.printState:
      self.showState()
    if self.returnMessages:
      return pTXT
    
  def msg_init(self):
    if self.opmode == SCCipher.OPMODE_CONTINUOUS:
      return
    if self.opmode == SCCipher.OPMODE_SINGLE:
      self.reset()
      return
    if self.opmode == SCCipher.OPMODE_SINGLE_WITHIV:
      self.reset()
      self.applyIV(self.iv)
      return
    if self.opmode == SCCipher.OPMODE_SINGLE_WITHRANDIV:
      self.reset()
      self.applyIV(self.genRandIV())
      return
    
  def random2Symbol(self, num_offsets=5, min_sec_ofs=-6, max_sec_ofs=6):
    self.metacipher = []
    for mainofs in [0,1]:
      secondary_offsets = list(range(min_sec_ofs, max_sec_ofs+1))
      shuffle(secondary_offsets)
      secondary_offsets = secondary_offsets[:num_offsets]
      self.metacipher.append(secondary_offsets)
    print(str(self.metacipher))
    
    self.offsetmetacipher = []
    for mainofs in [0,1]:
      secondary_offsets = list(range(min_sec_ofs, max_sec_ofs+1))
      shuffle(secondary_offsets)
      secondary_offsets = secondary_offsets[:num_offsets]
      self.offsetmetacipher.append(secondary_offsets)
    if self.mc_dispmode == SCCipher.DISPMODE_SEPMC:
      print(str(self.offsetmetacipher))
    
  def randomCrazy(self, num_secondary_operands=3, num_offsets=8, min_main_ofs=-6, max_main_ofs=6, min_sec_ofs=-6, max_sec_ofs=6):
    main_offsets = list(range(min_main_ofs,0))
    main_offsets.extend(range(2, max_main_ofs+1))
    shuffle(main_offsets)
    main_offsets = main_offsets[:num_secondary_operands]
    main_offsets.append(0)
    main_offsets.append(1)
    self.metacipher = []
    for mainofs in main_offsets:
      secondary_offsets = list(range(min_sec_ofs, max_sec_ofs+1))
      shuffle(secondary_offsets)
      secondary_offsets = secondary_offsets[:num_offsets]
      self.metacipher.append(secondary_offsets)
      
    print(str(self.metacipher))
    main_offsets = list(range(min_main_ofs,0))
    main_offsets.extend(range(2, max_main_ofs+1))
    shuffle(main_offsets)
    main_offsets = main_offsets[:num_secondary_operands]
    main_offsets.append(0)
    main_offsets.append(1)
    self.offsetmetacipher = []
    for mainofs in main_offsets:
      secondary_offsets = list(range(min_sec_ofs, max_sec_ofs+1))
      shuffle(secondary_offsets)
      secondary_offsets = secondary_offsets[:num_offsets]
      self.offsetmetacipher.append(secondary_offsets)
    if self.mc_dispmode == SCCipher.DISPMODE_SEPMC:
      print(str(self.offsetmetacipher))
  
  def defineMetacipher(self, operandOFS, *offsets):
    if len(offsets) == 0:
      return          
    removeMetacipher(operandOFS)
    mc = [operandOFS]
    self.metacipher.append(mc)
    if isinstance(offsets[0], list):
      mc.extend(offsets[0])
    else:
      mc.extend(offsets)
      
  def removeMetacipher(self, operandOFS): 
    for mc in self.metacipher:
      if mc[0] == operandOFS:
        self.metacipher.remove(mc)
        break
        
  def defineOfsetMetacipher(self, operandOFS, *offsets):
    if len(offsets) == 0:
      return          
    removeOfsMetacipher(operandOFS)
    mc = [operandOFS]
    self.ofsmetacipher.append(mc)
    if isinstance(offsets[0], list):
      mc.extend(offsets[0])
    else:
      mc.extend(offsets)
      
  def removeOffsetMetacipher(self, operandOFS): 
    for mc in self.ofsmetacipher:
      if mc[0] == operandOFS:
        self.ofsmetacipher.remove(mc)
        break
  
  # feed a plaintext data to the system, but do nothing with the result
  def digest(self, pDATA):
    literals = []
    if isinstance(pDATA, str):
      for char in pDATA:
        PTval = self.lexvalues.get(char)
        if PTval != None:
          PTpos = self.state.index(PTval)
          self.round(PTpos) 
    elif isinstance(pDATA, list):
      for PTval in pDATA:
        PTpos = self.state.index(PTval)
        self.round(PTpos) 
    
  def round(self, PTpos):    
    MCtransfers = []    
    for MCentry in self.metacipher:  
      MCmainofs = MCentry[0]
      MCpos = (PTpos+MCmainofs) % self.klen
      # MCentry = self.metacipher[MCmainofs]
      MCoperand = self.state[MCpos]
      MCtarget = 0
      MCdisplacement = 0
      for i in range(1, len(MCentry)):
        symbolval = self.state[ (MCpos+MCentry[i])%self.klen ]
        prevsymbolval = self.state[ (MCpos+MCentry[i]-1)%self.klen ]
        MCtarget += symbolval
        MCdisplacement <<= 1
        MCdisplacement |= (symbolval > prevsymbolval)
      MCtarget %= self.klen
      if self.mc_dispmode == SCCipher.DISPMODE_SEPMC:
        MCdisplacement = 0
        for OFSMCentry in self.offsetmetacipher: 
          if MCmainofs != OFSMCentry[0]:
            continue
          for i in range(1, len(OFSMCentry)):
            MCdisplacement += self.state[ (MCpos+OFSMCentry[i])%self.klen ]
          MCdisplacement %= self.klen
      MCtransfers.append([MCmainofs, MCoperand, MCtarget, MCdisplacement])
    
    for transfer in MCtransfers:
      MCmainofs = transfer[0]
      MCoperand = transfer[1]
      MCtarget = transfer[2]
      MCdisplacement = transfer[3]
      
      if self.mc_dispmode == SCCipher.DISPMODE_CONSTANT:
        MCdisplacement = self.mc_dispconst
      elif self.mc_dispmode == SCCipher.DISPMODE_BINARY:
        MCdisplacement += self.mc_dispconst
      elif self.mc_dispmode == SCCipher.DISPMODE_TRUNCATED_BINARY:
        MCdisplacement = self.mc_dispconst + MCdisplacement & self.mc_dispmask
      # if self.mc_dispmode == SCCipher.DISPMODE_SEPMC:
        # Use MCdisplacement as-is
        
      
      MCoperandpos = self.state.index(MCoperand)
      MCtargetpos = (self.state.index(MCtarget)+MCdisplacement)%self.klen
      
      if MCtargetpos < 0:
        MCtargetpos += self.klen
      if MCtargetpos >= self.klen:
        MCtargetpos -= self.klen
      if MCtargetpos > MCoperandpos:
        MCtargetpos -= 1
      self.state.remove(MCoperand)
      self.state.insert(MCtargetpos, MCoperand)
      
      
      
  def intro():  
    print("""ShuffleCrypt test script loaded. 
ShuffleCrypt is an oddball cryptosystem which [at least until a reasonable cryptanalysis can be undertaken] you would we well-advised not to use for any serious purpose.

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
    
  # MetaCipher operand displacement modes (SCCipher.mc_dispmode)  (the mechanism that conceals metacipher sums)
  DISPMODE_TRUNCATED_BINARY=0   # operand displacement:  mc_dispconst + (displacement & mc_dispmask)
  DISPMODE_BINARY=1             # operand displacement:  mc_dispconst + displacement
  DISPMODE_CONSTANT=2           # operand displacement:  mc_dispconst
  DISPMODE_SEPMC=3              # operand displacement:  compute other metaciphers to generate a displacement value""")

SCCipher.intro()