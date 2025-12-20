{
  description = "A bridge between Gleam and GJS!";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    flakelight.url = "github:nix-community/flakelight";
    flakelight.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { flakelight, ... }@inputs:
    flakelight ./.
    {
      inherit inputs;
      devShell.packages = pkgs: with pkgs; [
        gleam
        just
        erlang-language-platform
      ] ++ (with beam28Packages; [
        erlang
        erlfmt
        rebar3
      ]);
    };
}
