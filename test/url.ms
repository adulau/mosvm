; Copyright (C) 2006, Ephemeral Security, LLC 
;  
; This library is free software; you can redistribute it and/or modify it  
; under the terms of the GNU Lesser General Public License as published by  
; the Free Software Foundation; either version 2.1 of the License, or (at  
; your option) any later version. 
;  
; This library is distributed in the hope that it will be useful, but WITHOUT  
; ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or  
; FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License  
; for more details. 
;  
; You should have received a copy of the GNU Lesser General Public License  
; along with this library; if not, write to the Free Software Foundation,  
; Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA  
;  

(import "lib/test")
(import "lib/url")

(enable-spot-tests)

(s: (string->url "/xyz/123#aleph"))
(t: (eqv? (url-scheme _) #f))
(t: (eqv? (url-auth _) #f))
(t: (eqv? (url-path _) "/xyz/123"))
(t: (eqv? (url-query _) #f))
(t: (eqv? (url-frag _) "aleph"))
(t: (eqv? (url->string _) "/xyz/123#aleph"))

(s: (string->url "ftp://ftp.is.co.za/rfc/rfc1808.txt"))
(t: (eqv? (url-scheme _) "ftp"))
(t: (eqv? (url-auth _) "ftp.is.co.za"))
(t: (eqv? (url-path _) "/rfc/rfc1808.txt"))
(t: (eqv? (url-query _) #f))
(t: (eqv? (url-frag _) #f))
(t: (eqv? (url->string _) "ftp://ftp.is.co.za/rfc/rfc1808.txt"))

(s: (string->url "ftp://ftp.is.co.za/rfc/rfc1808.txt#frag1"))
(t: (eqv? (url-scheme _) "ftp"))
(t: (eqv? (url-auth _) "ftp.is.co.za"))
(t: (eqv? (url-path _) "/rfc/rfc1808.txt"))
(t: (eqv? (url-query _) #f))
(t: (eqv? (url-frag _) "frag1"))
(t: (eqv? (url->string _) "ftp://ftp.is.co.za/rfc/rfc1808.txt#frag1"))

(s: (string->url "ldap://[2001:db8::7]/c=GB?objectClass?one"))
(t: (eqv? (url-scheme _) "ldap"))
(t: (eqv? (url-auth _) "[2001:db8::7]"))
(t: (eqv? (url-path _) "/c=GB"))
(t: (eqv? (url-query _) "objectClass?one"))
(t: (eqv? (url-frag _) #f))
(t: (eqv? (url->string _) "ldap://[2001:db8::7]/c=GB?objectClass?one"))

(s: (string->url "mailto:John.Doe@example.com"))
(t: (eqv? (url-scheme _) "mailto"))
(t: (eqv? (url-auth _) #f))
(t: (eqv? (url-path _) "John.Doe@example.com"))
(t: (eqv? (url-query _) #f))
(t: (eqv? (url-frag _) #f))
(t: (eqv? (url->string _) "mailto:John.Doe@example.com"))

(s: (string->url "news:comp.infosystems.www.servers.unix"))
(t: (eqv? (url-scheme _) "news"))
(t: (eqv? (url-auth _) #f))
(t: (eqv? (url-path _) "comp.infosystems.www.servers.unix"))
(t: (eqv? (url-query _) #f))
(t: (eqv? (url-frag _) #f))
(t: (eqv? (url->string _) "news:comp.infosystems.www.servers.unix"))

(s: (string->url "tel:+1-816-555-1212"))
(t: (eqv? (url-scheme _) "tel"))
(t: (eqv? (url-auth _) #f))
(t: (eqv? (url-path _) "+1-816-555-1212"))
(t: (eqv? (url-query _) #f))
(t: (eqv? (url-frag _) #f))
(t: (eqv? (url->string _) "tel:+1-816-555-1212"))

(s: (string->url "telnet://192.0.2.16:80/"))
(t: (eqv? (url-scheme _) "telnet"))
(t: (eqv? (url-auth _) "192.0.2.16:80"))
(t: (eqv? (url-path _) "/"))
(t: (eqv? (url-query _) #f))
(t: (eqv? (url-frag _) #f))
(t: (eqv? (url->string _) "telnet://192.0.2.16:80/"))

(s: (string->url "urn:oasis:names:specification:docbook:dtd:xml:4.1.2"))
(t: (eqv? (url-scheme _) "urn"))
(t: (eqv? (url-auth _) #f))
(t: (eqv? (url-path _) "oasis:names:specification:docbook:dtd:xml:4.1.2"))
(t: (eqv? (url-query _) #f))
(t: (eqv? (url-frag _) #f))
(t: (eqv? (url->string _) 
          "urn:oasis:names:specification:docbook:dtd:xml:4.1.2"))

