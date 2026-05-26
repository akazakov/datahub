{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = [
    pkgs.jdk21
    pkgs.krb5          # provides krb5-config for `kerberos` and `gssapi` wheels
    pkgs.openldap      # headers for `python-ldap`
    pkgs.cyrus_sasl    # SASL headers (python-ldap, pure-sasl)
    pkgs.pkg-config
    pkgs.neovim
  ];

  shellHook = ''
    export JAVA_HOME="${pkgs.jdk21}/lib/openjdk"
    export PATH="$JAVA_HOME/bin:$PATH"

    # Nix splits krb5 into separate -dev (headers) and -lib outputs.
    # gssapi's setup.py probes for gssapi/gssapi_ext.h under the prefix
    # reported by `krb5-config --prefix`, which is the -lib path with no
    # include/ tree, so HAS_GSSAPI_EXT_H never gets defined and the S4U
    # symbols vanish at compile time. Force-define it here.
    export CFLAGS="''${CFLAGS:-} -DHAS_GSSAPI_EXT_H"
  '';
}
