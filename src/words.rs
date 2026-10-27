//! Keys, said out loud.
//!
//! LocalSend labels a device with a random word pair -- "Too Much Tuna",
//! "Yellow Iguana" -- and it is the most pleasant thing about using it. But
//! there the words are a *name*: the device picks them, so they tell two
//! phones apart on a screen and prove nothing. Anyone can be Yellow Iguana.
//!
//! Here the words are derived from the signing key, so they are a
//! fingerprint that happens to be sayable. Nobody chooses their own words,
//! and two machines showing the same ones are holding the same key. That is
//! the whole pairing step, in a form you can read across a room.
//!
//! ## Two lengths, because one length cannot do both jobs
//!
//! A single pair is 16 bits. Lovely to read, and useless as a security
//! check: an attacker generates Ed25519 keypairs until theirs also renders
//! "yellow iguana", which is about 65,000 tries -- under a second. So the
//! pair is a LABEL, for telling entries apart in a list, and nothing is ever
//! confirmed against it.
//!
//! `fingerprint` is four pairs, 64 bits, taken from a sha256 of the key. That
//! is the one a person confirms. Grinding keys to hit a chosen 64-bit value
//! is out of reach in a way 16 bits is not, and eight words is still
//! something you can say to someone standing at another laptop -- which an
//! SSH fingerprint or a Signal safety number is not.
//!
//! ## The label is NOT a prefix of the fingerprint, and the docs used to say
//! it was
//!
//! Both come from the same function, so for a key with no encryption half the
//! label is the fingerprint's first pair. For a contact you can seal to it is
//! not: the fingerprint covers `sign ␟ box` and the label covers `sign`, so
//! they are two values out of two different hashes that merely look alike.
//!
//! This note used to claim the label was "always the first pair of the
//! fingerprint", and offered that as a reason a reader could trust a glance
//! at the short one. `gage fingerprint` printed both on adjacent lines.
//! README and `spec.md` repeated it. All of it was wrong for every sealable
//! contact, which is to say for every ordinary one -- found by review.
//!
//! The label cannot be computed over both halves instead, which is the part
//! worth understanding rather than working around: a manifest carries the
//! sender's signing key alone, so the signing-only label is the ONLY nickname
//! a receiver can derive for a sender it has no contact entry for. It has to
//! stay what it is. So the claim went instead, here and everywhere it was
//! repeated, and the two values are now labelled for what they each cover.

// Laid out eight to a line on purpose: these are data tables a person
// proof-reads for duplicates and typos, and one word per line is 256
// lines that cannot be scanned. rustfmt would do exactly that.
#[rustfmt::skip]
pub const ADJECTIVES: [&str; 256] = [
    "amber", "ancient", "arctic", "autumn", "azure", "balmy", "bitter", "blank",
    "bold", "brave", "brick", "bright", "brisk", "bronze", "buoyant", "calm",
    "candid", "carved", "cedar", "chalky", "cheerful", "chilly", "chosen", "civic",
    "clean", "clear", "clever", "cobalt", "coral", "costly", "cosmic", "crimson",
    "crisp", "cryptic", "curious", "daily", "damp", "dapper", "daring", "dawn",
    "deep", "dense", "dewy", "distant", "dormant", "dotted", "downy", "drifting",
    "dusky", "eager", "early", "earnest", "eastern", "easy", "elder", "electric",
    "elegant", "ember", "empty", "endless", "equal", "even", "exact", "faint",
    "famous", "fancy", "feral", "fertile", "fierce", "final", "flaxen", "fleet",
    "flinty", "fluent", "foggy", "fond", "formal", "frank", "frosty", "frugal",
    "gallant", "gentle", "giant", "gilded", "glad", "glassy", "gleaming", "golden",
    "graceful", "grand", "granite", "grassy", "gravel", "greater", "green", "grey",
    "hollow", "honest", "humble", "husky", "icy", "idle", "indigo", "inland",
    "inner", "ivory", "jagged", "jolly", "joyful", "keen", "kindly", "lacy",
    "lanky", "lasting", "latter", "lavish", "lean", "level", "light", "lilac",
    "limber", "linen", "little", "lively", "lofty", "lonely", "loyal", "lucid",
    "lunar", "magnetic", "marble", "marine", "mellow", "merry", "mild", "mindful",
    "minor", "misty", "modest", "molten", "mossy", "muted", "narrow", "native",
    "nautical", "neat", "nimble", "noble", "northern", "novel", "oaken", "olive",
    "opal", "orderly", "outer", "pale", "patient", "peach", "pearl", "placid",
    "plain", "pleasant", "plucky", "polar", "polished", "prairie", "prime", "private",
    "prompt", "proud", "prudent", "pure", "quaint", "quick", "quiet", "rapid",
    "rare", "raven", "ready", "regal", "restless", "rich", "rising", "roasted",
    "robust", "rocky", "rosy", "royal", "ruddy", "rugged", "rustic", "sable",
    "sacred", "sandy", "scarlet", "seaside", "secret", "serene", "shady", "shallow",
    "sharp", "sheer", "shining", "shrewd", "silent", "silken", "silver", "simple",
    "singing", "sleepy", "slender", "smoky", "smooth", "snowy", "solar", "solemn",
    "solid", "somber", "southern", "sparse", "spiced", "splendid", "spotless", "spry",
    "stable", "staid", "starry", "steady", "steep", "stern", "still", "stony",
    "stout", "straight", "striking", "subtle", "sudden", "sunlit", "sunny", "supple",
    "swift", "tall", "tame", "tangy", "tender", "thrifty", "tidal", "tidy",
    "timely", "tiny", "towering", "tranquil", "true", "twilight", "twin", "umber",
];

// Laid out eight to a line on purpose: these are data tables a person
// proof-reads for duplicates and typos, and one word per line is 256
// lines that cannot be scanned. rustfmt would do exactly that.
#[rustfmt::skip]
pub const NOUNS: [&str; 256] = [
    "acorn", "alcove", "almond", "anchor", "anvil", "apple", "arbor", "archer",
    "armour", "arrow", "ashes", "aspen", "atlas", "aurora", "avenue", "awning",
    "badger", "ballad", "bamboo", "banner", "barley", "basin", "beacon", "beagle",
    "bedrock", "beetle", "bellows", "bergamot", "birch", "bison", "bistro", "blanket",
    "bluff", "bobcat", "bonfire", "boulder", "bramble", "brandy", "bridge", "bristle",
    "brook", "bugle", "bullfinch", "burrow", "cabin", "cactus", "cairn", "canopy",
    "canyon", "caravan", "cardinal", "carrot", "cascade", "cedar", "cellar", "chalice",
    "chapel", "chestnut", "chimney", "cinder", "cistern", "citadel", "clover", "cobble",
    "compass", "condor", "copper", "coral", "cornice", "cottage", "coyote", "cradle",
    "crater", "cricket", "crocus", "crossing", "crowbar", "cypress", "daffodil", "dahlia",
    "dairy", "damson", "delta", "derrick", "dingo", "dolphin", "domino", "dormouse",
    "dovecote", "dragon", "drumlin", "dune", "eagle", "echo", "eddy", "elkhorn",
    "ember", "emerald", "estuary", "falcon", "fathom", "fennel", "fernlead", "ferry",
    "fiddle", "finch", "firefly", "fjord", "flagon", "flannel", "flint", "foghorn",
    "forest", "fountain", "foxglove", "fulcrum", "furrow", "gable", "gallery", "gander",
    "garnet", "gazebo", "geyser", "ginger", "glacier", "glade", "granary", "granite",
    "grotto", "gull", "gully", "hamlet", "harbor", "harvest", "hawthorn", "hazel",
    "heather", "hedgerow", "hemlock", "heron", "hickory", "hollow", "hornet", "hostel",
    "iceberg", "iguana", "inkwell", "ironwood", "island", "ivory", "jackdaw", "jasmine",
    "jetty", "juniper", "kestrel", "kettle", "keystone", "kingfisher", "kiosk", "kittiwake",
    "lagoon", "lantern", "larkspur", "lattice", "lavender", "ledger", "lemon", "lichen",
    "lighthouse", "lilac", "limestone", "linnet", "lintel", "lobster", "locket", "lodestone",
    "lupine", "lyrebird", "magnolia", "mallard", "mandolin", "mangrove", "mantle", "maple",
    "marina", "marmot", "marsh", "meadow", "medley", "menhir", "mesa", "millrace",
    "mineral", "minnow", "mistral", "mitten", "moorland", "mortar", "mosaic", "mustang",
    "myrtle", "nectar", "nettle", "newel", "nightjar", "nutmeg", "oakleaf", "obelisk",
    "ocelot", "okapi", "orchard", "oriole", "osprey", "otter", "outcrop", "oxbow",
    "paddock", "pagoda", "palisade", "pampas", "pangolin", "pantry", "papyrio", "parapet",
    "parsnip", "partridge", "pasture", "pavilion", "peacock", "pebble", "pelican", "pendant",
    "penguin", "peony", "pewter", "pheasant", "pigeon", "pillar", "pinnacle", "piston",
    "plateau", "plover", "plumage", "poppy", "porcupine", "portico", "possum", "prairie",
    "primrose", "puffin", "pumice", "quarry", "quartz", "quilt", "quiver", "rampart",
];

/// Four pairs, 64 bits: the value a person confirms when pairing.
///
/// **Covers both halves of the identity when both are known**, and that is
/// not a detail. A reviewer found that computing it over the signing key
/// alone broke the entire ceremony: the token people exchange is
/// `signkey.boxkey`, and only the first half was confirmed. An attacker on
/// the channel the token travels over -- the exact threat these words exist
/// for -- leaves the signing half untouched and substitutes its own box key.
/// The recipient compares four word-pairs, hears an exact match, because the
/// signing key really is the sender's, and then seals every message to the
/// attacker. Signatures still verify. `SENDER VERIFIED` still prints. The
/// attacker decrypts, re-seals to the real key and forwards, and both
/// parties performed the confirmation correctly.
///
/// So the value confirmed is over both keys. Changing this changes every
/// fingerprint, which means contacts confirmed under the old scheme have to
/// be confirmed again -- the right cost, because what they confirmed did not
/// cover what it needed to.
pub fn fingerprint_of(sign_key_b64: &str, box_key_b64: Option<&str>) -> String {
    match box_key_b64 {
        // 0x1f between them, so `a` + `bc` and `ab` + `c` cannot collide.
        // Each half trimmed, not just the concatenation: a key pasted out of
        // a terminal picks up whitespace, and if that changed the words a
        // correct pairing would read as an attack.
        Some(b) => pairs(&format!("{}\u{1f}{}", sign_key_b64.trim(), b.trim()), 4).join(" · "),
        None => pairs(sign_key_b64, 4).join(" · "),
    }
}

/// The signing key alone. For a contact with no encryption key on file --
/// which `add_contact` still supports, since contacts predating encryption
/// are verifiable and not sealable -- there is nothing else to cover. Every
/// caller that has a box key must pass it: a confirmation that silently
/// covers less than the thing being confirmed is worse than none, because
/// people act on it.
pub fn fingerprint(sign_key_b64: &str) -> String {
    fingerprint_of(sign_key_b64, None)
}

/// One pair, 16 bits: a label for telling devices apart in a list.
///
/// Never confirmed against. See the module note on why.
///
/// **Signing key only, and it has to be.** A bundle's manifest carries the
/// sender's signing key and nothing else, so this is the only key-derived
/// nickname a receiver can compute for a sender at all. That is the job:
/// `open` prints it to say "this key calls itself its own label", the viewer
/// lists connection requests by it, and `is_a_name_you_use` checks it,
/// because it is what a reader of yours would recognise.
///
/// The consequence, which cost a review to find: for a contact you can seal
/// to, this is **not** a prefix of the four-pair fingerprint. The fingerprint
/// covers `sign ␟ box`; this covers `sign`. Two values from two hashes. The
/// module note above used to promise otherwise without the qualifier, and
/// `gage fingerprint` printed both on adjacent lines -- so a person who
/// glanced at one and skipped the other believed they had compared a prefix
/// of the thing that matters, and had compared a different value that looked
/// like one. Nothing here can fix that by computing differently; what had to
/// change is that the output and the documents stop implying it.
pub fn label(sign_key_b64: &str) -> String {
    pairs(sign_key_b64, 1).remove(0)
}

/// Compare a word-pair echo against a fingerprint.
///
/// Normalised on separators and case, not on the words: a human reading four
/// pairs down a phone line and typing them back will differ on punctuation
/// and will not differ on words. Requiring byte equality would fail honest
/// confirmations; accepting a subset would accept a guess.
///
/// Lives here rather than beside one caller because three paths compare an
/// echo -- `gage confirm`, the viewer and the MCP server -- and three
/// normalisers that drift are three different ideas of what counts as a
/// match.
pub fn echo_matches(echo: &str, fingerprint: &str) -> bool {
    let norm = |s: &str| -> Vec<String> {
        s.to_lowercase()
            .split(|c: char| !c.is_ascii_alphabetic())
            .filter(|w| !w.is_empty())
            .map(|w| w.to_string())
            .collect()
    };
    let a = norm(echo);
    !a.is_empty() && a == norm(fingerprint)
}

/// `n` adjective-noun pairs, read from a sha256 of the key.
///
/// Hashed rather than read off the key directly, so the words do not expose a
/// chosen prefix of the key material and a near-miss in the words does not
/// imply a near-miss in the key.
pub fn pairs(sign_key_b64: &str, n: usize) -> Vec<String> {
    let h = crate::bundle::sha256_hex(sign_key_b64.trim().as_bytes());
    let bytes: Vec<u8> = (0..h.len() / 2)
        .map(|i| u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).unwrap_or(0))
        .collect();
    (0..n)
        .map(|i| {
            let a = ADJECTIVES[bytes[i * 2] as usize];
            let b = NOUNS[bytes[i * 2 + 1] as usize];
            format!("{a} {b}")
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn the_lists_are_full_and_have_no_repeats() {
        // A repeated word costs entropy silently: two different keys would
        // render the same words with no sign that anything is wrong.
        assert_eq!(ADJECTIVES.len(), 256);
        assert_eq!(NOUNS.len(), 256);
        assert_eq!(ADJECTIVES.iter().collect::<BTreeSet<_>>().len(), 256);
        assert_eq!(NOUNS.iter().collect::<BTreeSet<_>>().len(), 256);
        for w in ADJECTIVES.iter().chain(NOUNS.iter()) {
            assert!(
                w.chars().all(|c| c.is_ascii_lowercase()),
                "{w} is not plain lowercase ascii, so it cannot be read aloud reliably"
            );
            assert!((3..=11).contains(&w.len()), "{w} is a bad length to say");
        }
    }

    #[test]
    fn the_label_is_the_first_pair_of_the_fingerprint() {
        // So someone who glances at the label has compared a real prefix of
        // the value that matters, not a separate lookalike.
        let k = "yomSmC3TalJ5IM+H0yvkhhWVab4ujiAVIQFR4WvdXiM=";
        assert!(fingerprint(k).starts_with(&label(k)));
        assert_eq!(fingerprint(k).split(" · ").count(), 4);
        assert_eq!(label(k).split(' ').count(), 2);

        // And the case the first version of this test could not see, because
        // it only ever passed a bare signing key: once an encryption key is
        // on file the fingerprint covers both halves and the label does not,
        // so the prefix relationship ENDS. Asserted rather than merely
        // commented, because three documents claimed the opposite and no
        // test contradicted them.
        let b = "7amQkpwKszbeF801n5EzMRm4jQlx3BylW8c59lsDcX0=";
        let fp = fingerprint_of(k, Some(b));
        assert!(
            !fp.starts_with(&label(k)),
            "the label is a prefix of a sealable key's fingerprint, so either the \
             fingerprint stopped covering the encryption key or the two hashes \
             collided -- and every piece of output that distinguishes them is now wrong"
        );
    }

    #[test]
    fn an_echo_matches_on_words_not_on_punctuation() {
        let fp = fingerprint("yomSmC3TalJ5IM+H0yvkhhWVab4ujiAVIQFR4WvdXiM=");
        assert!(echo_matches(&fp, &fp));
        assert!(echo_matches(&fp.replace(" · ", ", "), &fp));
        assert!(echo_matches(&fp.to_uppercase(), &fp));
        assert!(echo_matches(&format!("  {fp}  "), &fp));
        // A subset is not a match: three of four pairs is a guess with one
        // pair's worth of work saved.
        let three = fp.split(" · ").take(3).collect::<Vec<_>>().join(" · ");
        assert!(!echo_matches(&three, &fp));
        assert!(!echo_matches("", &fp));
        // Word order carries the value, so a reordering is not a match.
        let mut parts: Vec<&str> = fp.split(" · ").collect();
        parts.reverse();
        assert!(!echo_matches(&parts.join(" · "), &fp));
    }

    #[test]
    fn different_keys_say_different_things() {
        let a = fingerprint("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
        let b = fingerprint("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=");
        assert_ne!(a, b);
        // And the same key always says the same thing, on every machine:
        // the pairing step is worthless if it is not reproducible.
        assert_eq!(
            a,
            fingerprint("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
        );
    }

    #[test]
    fn surrounding_whitespace_does_not_change_the_words() {
        // A key pasted out of a terminal picks up a newline. If that changed
        // the fingerprint, two machines holding the identical key would show
        // different words and a correct pairing would read as an attack.
        let k = "yomSmC3TalJ5IM+H0yvkhhWVab4ujiAVIQFR4WvdXiM=";
        assert_eq!(fingerprint(k), fingerprint(&format!("  {k}\n")));
    }

    #[test]
    fn the_words_cover_the_encryption_key_too() {
        // This test replaces one that asserted the opposite, and the
        // reasoning it carried is what caused the hole: it argued the words
        // "must be computed from the signing half alone, or a contact added
        // from a full token and one added from a bare key would disagree
        // about the same person." That optimised for consistency and gave
        // away coverage. They SHOULD disagree -- they are not the same
        // security claim, because one can be sealed to and the other cannot.
        //
        // The attack it allowed: an attacker on the channel substitutes only
        // the box half. The recipient compares four word-pairs for the
        // signing key, hears a perfect match, and then seals every message
        // to the attacker.
        let sign = "yomSmC3TalJ5IM+H0yvkhhWVab4ujiAVIQFR4WvdXiM=";
        let good = "7amQkpwKszbeF801n5EzMRm4jQlx3BylW8c59lsDcX0=";
        let evil = "uqYqbyJEhhofgimN/j016/IpGKrK3lp/1CN7JdUHYAc=";
        assert_ne!(
            fingerprint_of(sign, Some(good)),
            fingerprint_of(sign, Some(evil)),
            "substituting the encryption key did not change the words"
        );
        // And covering both is not the same as covering the signing key.
        assert_ne!(fingerprint_of(sign, Some(good)), fingerprint_of(sign, None));
        // The separator stops `a`+`bc` colliding with `ab`+`c`.
        assert_ne!(
            fingerprint_of("ab", Some("c")),
            fingerprint_of("a", Some("bc"))
        );
    }

    #[test]
    fn whitespace_in_either_half_does_not_change_the_words() {
        let k = "yomSmC3TalJ5IM+H0yvkhhWVab4ujiAVIQFR4WvdXiM=";
        let b = "7amQkpwKszbeF801n5EzMRm4jQlx3BylW8c59lsDcX0=";
        assert_eq!(
            fingerprint_of(k, Some(b)),
            fingerprint_of(&format!("  {k}\n"), Some(&format!(" {b} ")))
        );
    }
}
