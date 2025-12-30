const re = '^[^0-9]*(?<major>[0-9]+)\.(?<minor>[0-9]+)\.(?<patch>[0-9]+)(?<special>[0-9A-Za-z-\.]*)$'

export def parse [version: string]: nothing -> any {
  {
    major: ($version | str replace -r $re "$major" | into int)
    minor: ($version | str replace -r $re "$minor" | into int)
    patch: ($version | str replace -r $re "$patch" | into int)
    special: ($version | str replace -r $re "$special")
  }
}

export def make []: any -> string {
  $in | format pattern "{major}.{minor}.{patch}{special}"
}

export def lt [version_b: any]: any -> bool {
  let version_a = $in
  # A.MAJOR < B.MAJOR
  ($version_a.major < $version_b.major or
    # A.MAJOR == B.MAJOR and A.MINOR < B.MINOR
    ($version_a.major == $version_b.major and $version_a.minor < $version_b.minor) or
    # A.MAJOR == B.MAJOR and A.MINOR == B.MINOR and A.PATCH < B.PATCH
    ($version_a.major == $version_b.major and $version_a.minor == $version_b.minor and
      $version_a.patch < $version_b.patch) or
    # A.SPECIAL and B.SPECIAL
    (($version_a.special | is-not-empty) and ($version_b.special | is-not-empty)) or
    # A.SPECIAL and !B.SPECIAL
    (($version_a.special | is-not-empty) and ($version_b.special | is-empty)) or
    # A.SPECIAL < B.SPECIAL
    $version_a.special < $version_b.special)
}

export def gt [version_b: any]: any -> bool {
  let version_a = $in
  not (($version_a | lt $version_b) or ($version_a | eq $version_b))
}
