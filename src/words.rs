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
//! Both come from the same hash in the same order, so the label is always the
//! first pair of the fingerprint. A reader comparing only the label is
//! comparing a real prefix of the thing that matters, rather than a different
//! value that happens to look similar.

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
pub fn fingerprint(sign_key_b64: &str) -> String {
    pairs(sign_key_b64, 4).join(" · ")
}

/// One pair, 16 bits: a label for telling devices apart in a list.
///
/// Never confirmed against. See the module note on why.
pub fn label(sign_key_b64: &str) -> String {
    pairs(sign_key_b64, 1).remove(0)
}

/// `n` adjective-noun pairs, read from a sha256 of the key.
///
/// Hashed rather than read off the key directly, so the words do not expose a
/// chosen prefix of the key material and a near-miss in the words does not
/// imply a near-miss in the key.
fn pairs(sign_key_b64: &str, n: usize) -> Vec<String> {
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
    }

    #[test]
    fn different_keys_say_different_things() {
        let a = fingerprint("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
        let b = fingerprint("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=");
        assert_ne!(a, b);
        // And the same key always says the same thing, on every machine:
        // the pairing step is worthless if it is not reproducible.
        assert_eq!(a, fingerprint("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="));
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
    fn a_full_token_is_not_the_same_as_its_signing_half() {
        // `ctx whoami` prints signpub.boxpub. The words must be computed from
        // the signing half alone, or a contact added from a full token and one
        // added from a bare key would disagree about the same person.
        let sign = "yomSmC3TalJ5IM+H0yvkhhWVab4ujiAVIQFR4WvdXiM=";
        let full = format!("{sign}.SOMEBOXKEY");
        assert_ne!(fingerprint(sign), fingerprint(&full));
    }
}
