{
  description = "Practical Constant-Size Delegatable Anonymous Credentials in Python";

  inputs = {
    nixpkgs.url = github:nixOS/nixpkgs;
  };

  outputs = { self, nixpkgs }:
  let
    system = "x86_64-linux";
    pkgs = import nixpkgs { inherit system; };
    python = pkgs.python311;
    dependencyFixes = {
      # ensure openssl is visible
      preConfigure = ''
        export LD_LIBRARY_PATH=${pkgs.lib.makeLibraryPath [
          pkgs.openssl
          python.pkgs.asn1crypto
        ]}
        export LDFLAGS="-L${pkgs.openssl.out}/lib"
        export CFLAGS="-I${pkgs.openssl.dev}/include"
      '';
      # rename msgpack-python to msgpack
      postPatch = ''
        substituteInPlace setup.py \
                --replace 'msgpack-python' msgpack
        substituteInPlace requirements.txt \
                --replace 'msgpack-python' msgpack
      '';
    };
    petlib = python.pkgs.buildPythonPackage (rec {
      pname = "petlib";
      version = "0.0.45-${src.rev}";
      src = pkgs.fetchFromGitHub {
        owner = "gdanezis";
        repo = "petlib";
        rev = "master";
        sha256 = "sha256-QPFgkXy/PG4nuJAHm2fuwtedmxWEoBYyLtVPXZmsZPw=";
      };
      propagatedBuildInputs = with python.pkgs; [
        pytest cffi pycparser future pytest-cov msgpack tox pkgs.openssl.out asn1crypto
      ];
    } // dependencyFixes);
    bplib = python.pkgs.buildPythonPackage (rec {
      pname = "bplib";
      version = "0.0.6-${src.rev}";
      src = pkgs.fetchFromGitHub {
        # use fork to fix https://github.com/gdanezis/bplib/issues/17
        owner = "caro3801";
        repo = "bplib";
        rev = "129533b70867ff73d9d84a206ecfd95ad77c0a5c";
        sha256 = "sha256-9gtrc/fg8IbIo65ydVErDg2qgWDcG5PSv/c32pk+Bus=";
      };
      propagatedBuildInputs = with python.pkgs; [
        petlib pytest pytest-runner
      ];
      doCheck = false;
    } // dependencyFixes);
    coconut-lib = python.pkgs.buildPythonPackage rec {
      pname = "coconut-lib";
      version = "1.3.1-${src.rev}";
      src = pkgs.fetchFromGitHub {
        owner = "asonnino";
        repo = "coconut";
        rev = "d45b1426e5aeba16c43abdd99a3ee5726edcd19e";
        sha256 = "sha256-NU6+XNNLbY7FyHPD69Tius8qg7MOb1sfM2K8kZQkiug=";
      };
      propagatedBuildInputs = with python.pkgs; [ petlib bplib tox ];
    };
    pythonEnv = python.withPackages (ps: with ps; [
      pytest pytest-runner petlib bplib coconut-lib numpy termcolor
    ]);
  in {
    devShells."${system}".default = pkgs.mkShell {
      buildInputs = [ pythonEnv ];
    };
  };
}
