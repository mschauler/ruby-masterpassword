# masterpassword.rb is an implemenation of the masterpassword-algorithm as descibed here: http://masterpasswordapp.com
#
# Copyright 2014 Markus Schauler
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.


require "scrypt"

# The password templates
TEMPLATES = {
  "Basic" => ["aaanaaan","aannaaan","aaannaaa"],
  "PIN" => ["nnnn"],
  "Maximum" => ["anoxxxxxxxxxxxxxxxxx", "axxxxxxxxxxxxxxxxxno"],
  "Medium" => ["CvcnoCvc","CvcCvcno"],
  "Short" => ["Cvcn"],
  "Long" => [
      "CvcvnoCvcvCvcv", "CvcvCvcvnoCvcv", "CvcvCvcvCvcvno", "CvccnoCvcvCvcv",
      "CvccCvcvnoCvcv", "CvccCvcvCvcvno", "CvcvnoCvccCvcv", "CvcvCvccnoCvcv",
      "CvcvCvccCvcvno", "CvcvnoCvcvCvcc", "CvcvCvcvnoCvcc", "CvcvCvcvCvccno",
      "CvccnoCvccCvcv", "CvccCvccnoCvcv", "CvccCvccCvcvno", "CvcvnoCvccCvcc",
      "CvcvCvccnoCvcc", "CvcvCvccCvccno", "CvccnoCvcvCvcc", "CvccCvcvnoCvcc", "CvccCvcvCvccno"
     ],
  "Name" => ["cvccvcvcv"],
  "Phrase" => ["cvcc cvc cvccvcv cvc", "cvc cvccvcvcv cvcv", "cv cvccv cvc cvcvccv"]
  }

# definition of the character classes used by the password templates
CHAR_CLASS = {
  'a' => "AEIOUaeiouBCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxyz",
  'A' => "AEIOUBCDFGHJKLMNPQRSTVWXYZ",
  'c' => "bcdfghjklmnpqrstvwxyz",
  'C' => "BCDFGHJKLMNPQRSTVWXYZ",
  'n' => "0123456789",
  'o' => "@&%?,=[]_:-+*$#!'^~;()/.",
  'v' => "aeiou",
  'V' => "AEIOU",
  'x' => "AEIOUaeiouBCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxyz0123456789!@#$%^&*()",
  ' ' => " "
}
  
##
# Calculates masterkey from name and secret
#
def calculate_masterkey(name,secret)
  salt = "com.lyndir.masterpassword" + [name.bytesize].pack("N") + name
  SCrypt::Engine.scrypt(secret, salt, 32768, 8, 2, 64)
end


##
# Calculates seed from masterkey, scope, sitename and counter value
# scope should be "com.lyndir.masterpassword.login" when calculating a login name,
# and "com.lyndir.masterpassword" otherwise
def calculate_seed(key, scope, sitename, counter)
  message = scope + [sitename.bytesize].pack("N") + sitename + [counter].pack("N")
  digest=OpenSSL::Digest.new('sha256')
  OpenSSL::HMAC.digest(digest,key,message)
end

## Calculates password from seed for a given template
def calculate_password(seed, tempclass)
  bytes=seed.bytes 
  templates = TEMPLATES[tempclass]
 
  template = templates[bytes.shift % templates.length]
  # for all chars in template, replace template character by member of corresponding character class
  template.chars.inject("") {|password, type| password += CHAR_CLASS[type][bytes.shift % (CHAR_CLASS[type].length)]}
end



# example
NAME= "Firstname Lastname"
SECRET = "My super-secret passphrase"
SITE = "www.mysite.com"
COUNTER = 1

masterkey= calculate_masterkey(NAME, SECRET)

# now calculate seed for loginname
seed = calculate_seed(masterkey, "com.lyndir.masterpassword.login", SITE ,COUNTER)

puts "Login\t#{calculate_password(seed,"Name")}\n"


# calculate seed for passwords 
seed = calculate_seed(masterkey, "com.lyndir.masterpassword", SITE, COUNTER)

# generate and output all defined password types
TEMPLATES.keys.each do |key|
  next if key == "Name" # skip login-name template 
  puts "#{key}\t#{calculate_password(seed,key)}" 
end
