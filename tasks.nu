#!/usr/bin/env nu

use ./nu/semver.nu

def main [] {}

def "main format" []: nothing -> nothing {
  match (which nix | is-not-empty) {
    true => (nix fmt)
    false => {
      erlfmt -w src/*.erl
      gleam format test/*.gleam src/*.gleam
    }
  }
}

def "main bump" [
  part: string
  --create-tag
]: nothing -> nothing {
  let package = open gleam.toml
  let version = semver parse $package.version
  
  let new_version = match $part {
    "epoch" => {
      let epoch = if ($version.major / 1000 >= 1) {
        $version.major / 1000 | math floor
      } else {
        0
      }
      let major = $version.major mod 1000

      $version
      | update major (($epoch + 1) * 1000 + $major)
      | update minor 0
      | update patch 0
    }
    "major" => {
      $version
      | update major ($in.major + 1)
      | update minor 0
      | update patch 0
    }
    "minor" => {
      $version
      | update minor ($in.minor + 1)
      | update patch 0
    }
    "patch" => ($version | update patch ($in.patch + 1))
    $_ => {
      print $"Unknown epoch semver part: ($part)"
      exit 1
    }
  } | semver make 

  $package
  | update version $new_version
  | to toml
  | save -f gleam.toml

  git commit -m $"feat\(($new_version)\): bump version"

  if $create_tag {
    git tag $"v($new_version)"
  }
}
