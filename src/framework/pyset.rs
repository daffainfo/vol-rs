//! The order a Python set gives back its members.
//!
//! Several upstream plugins collect values in a set and then report them in
//! whatever order iteration hands them over. That order is not arbitrary: it
//! falls out of the hash table CPython builds, and it is stable for a given
//! sequence of insertions. Reproducing a listing exactly therefore means
//! reproducing the table.
//!
//! Only integers are needed here, and a Python integer hashes to itself, so
//! the table can be built from the values alone.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

/// The smallest table CPython allocates.
const MINIMUM_SIZE: usize = 8;
/// How many neighbouring slots are examined before the probe jumps.
const LINEAR_PROBES: usize = 9;
/// How fast the hash is consumed once probing starts jumping.
const PERTURB_SHIFT: u32 = 5;

/// A set of integers that hands its members back in CPython's order.
pub struct PythonSet {
    table: Vec<Option<u64>>,
    fill: usize,
    used: usize,
}

impl Default for PythonSet {
    fn default() -> Self {
        Self::new()
    }
}

impl PythonSet {
    pub fn new() -> Self {
        Self {
            table: vec![None; MINIMUM_SIZE],
            fill: 0,
            used: 0,
        }
    }

    fn mask(&self) -> u64 {
        self.table.len() as u64 - 1
    }

    /// Add a value, doing nothing if it is already a member.
    pub fn insert(&mut self, value: u64) {
        let mask = self.mask();
        let mut index = value & mask;
        let mut perturb = value;

        let slot = loop {
            // Neighbouring slots are only examined while they stay inside the
            // table. At the end of it the probe jumps straight away.
            let probes = if index + LINEAR_PROBES as u64 <= mask {
                LINEAR_PROBES
            } else {
                0
            };
            let mut free = None;
            for step in 0..=probes {
                let at = index as usize + step;
                match self.table[at] {
                    None => {
                        free = Some(at);
                        break;
                    }
                    Some(existing) if existing == value => return,
                    Some(_) => {}
                }
            }
            if let Some(at) = free {
                break at;
            }
            perturb >>= PERTURB_SHIFT;
            index = (index.wrapping_mul(5).wrapping_add(1).wrapping_add(perturb)) & mask;
        };

        self.table[slot] = Some(value);
        self.fill += 1;
        self.used += 1;

        // The table grows once it is three fifths full, to four times what it
        // holds.
        if self.fill as u64 * 5 >= mask * 3 {
            self.resize(self.used * 4);
        }
    }

    /// Whether a value is a member.
    pub fn contains(&self, value: u64) -> bool {
        self.table.iter().flatten().any(|entry| *entry == value)
    }

    pub fn len(&self) -> usize {
        self.used
    }

    pub fn is_empty(&self) -> bool {
        self.used == 0
    }

    /// The members, in the order iteration would hand them over.
    pub fn iter(&self) -> impl Iterator<Item = u64> + '_ {
        self.table.iter().flatten().copied()
    }
}

impl PythonSet {
    /// Rebuild the table at a larger size, reinserting in table order.
    fn resize(&mut self, minimum: usize) {
        let mut size = MINIMUM_SIZE;
        while size <= minimum {
            size <<= 1;
        }
        let old = std::mem::replace(&mut self.table, vec![None; size]);
        let mask = self.mask();

        for value in old.into_iter().flatten() {
            // A rebuild knows every value is new, so it looks only for a free
            // slot.
            let mut index = value & mask;
            let mut perturb = value;
            loop {
                if self.table[index as usize].is_none() {
                    self.table[index as usize] = Some(value);
                    break;
                }
                if index + LINEAR_PROBES as u64 <= mask {
                    let free = (1..=LINEAR_PROBES)
                        .map(|step| index as usize + step)
                        .find(|at| self.table[*at].is_none());
                    if let Some(at) = free {
                        self.table[at] = Some(value);
                        break;
                    }
                }
                perturb >>= PERTURB_SHIFT;
                index = (index.wrapping_mul(5).wrapping_add(1).wrapping_add(perturb)) & mask;
            }
        }
        self.fill = self.used;
    }
}

impl FromIterator<u64> for PythonSet {
    fn from_iter<I: IntoIterator<Item = u64>>(values: I) -> Self {
        let mut set = Self::new();
        for value in values {
            set.insert(value);
        }
        set
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn order(values: &[u64]) -> Vec<u64> {
        values.iter().copied().collect::<PythonSet>().iter().collect()
    }

    #[test]
    fn a_small_set_matches_the_interpreter() {
        assert_eq!(
            order(&[10612, 4944, 12938, 1583, 2374]),
            vec![2374, 12938, 1583, 4944, 10612]
        );
    }

    #[test]
    fn a_set_that_has_grown_once_matches_the_interpreter() {
        assert_eq!(
            order(&[
                17560, 3085, 11983, 19097, 1901, 16628, 7036, 1229, 2817, 14210, 13703, 2290
            ]),
            vec![2817, 14210, 13703, 1901, 3085, 11983, 1229, 2290, 16628, 17560, 19097, 7036]
        );
    }

    #[test]
    fn a_set_that_has_grown_twice_matches_the_interpreter() {
        assert_eq!(
            order(&[
                7887, 2973, 18057, 13911, 1937, 18529, 4057, 7316, 19104, 2028, 18911, 19188,
                12999, 1625, 7245, 1527, 18241, 4364, 9490, 13735, 4727, 17718, 3860, 18708,
                10109, 18359, 5923, 3377, 19058, 18718, 6157, 12203, 3193, 17949, 2058, 18494,
                1954, 6749, 16267, 17424
            ]),
            vec![
                18057, 2058, 16267, 4364, 6157, 17424, 1937, 9490, 7316, 3860, 18708, 2973,
                18718, 17949, 19104, 1954, 5923, 13735, 12203, 3377, 17718, 18359, 18494, 18241,
                12999, 7245, 7887, 13911, 1625, 4057, 6749, 18911, 18529, 4727, 2028, 19058,
                19188, 1527, 3193, 10109
            ]
        );
    }

    #[test]
    fn a_repeated_value_is_added_once() {
        let set: PythonSet = [5u64, 5, 5, 9].into_iter().collect();
        assert_eq!(set.len(), 2);
        assert!(set.contains(9));
    }
}
