{
  description = "ldapmap - Blind LDAP Injection Scanner and Extractor";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
      version = (builtins.fromTOML (builtins.readFile ./pyproject.toml)).project.version;
    in {
      packages = forAllSystems (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in {
          default = pkgs.python3Packages.buildPythonApplication {
            pname = "ldapmap";
            inherit version;
            pyproject = true;
            src = ./.;
            build-system = [ pkgs.python3Packages.setuptools ];
            dependencies = [ pkgs.python3Packages.requests ];
          };
        }
      );

      apps = forAllSystems (system: {
        default = {
          type = "app";
          program = "${self.packages.${system}.default}/bin/ldapmap";
        };
      });
    };
}
