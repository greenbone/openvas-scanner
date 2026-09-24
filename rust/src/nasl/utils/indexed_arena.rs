use std::marker::PhantomData;

/// This is an arena for items of type T along with a id/index type I.
/// The main point of this is to disallow removing already existing elements
/// so that returned ids always remain valid.
pub struct IndexedArena<I: ArenaIndex, T> {
    inner: Vec<T>,
    _marker: PhantomData<I>,
}

impl<I: ArenaIndex, T> IndexedArena<I, T> {
    pub(crate) fn add(&mut self, item: T) -> I {
        self.inner.push(item);
        I::from_index(self.inner.len() - 1)
    }

    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.inner.iter()
    }

    pub fn enumerate(&self) -> impl Iterator<Item = (I, &T)> {
        self.inner
            .iter()
            .enumerate()
            .map(|(i, t)| (I::from_index(i), t))
    }
}

impl<I: ArenaIndex, T> Default for IndexedArena<I, T> {
    fn default() -> Self {
        Self {
            inner: vec![],
            _marker: PhantomData,
        }
    }
}

impl<I: ArenaIndex, T: std::fmt::Debug> std::fmt::Debug for IndexedArena<I, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IndexedArena")
            .field("inner", &self.inner)
            .finish()
    }
}

impl<I: ArenaIndex, T> FromIterator<T> for IndexedArena<I, T> {
    fn from_iter<It: IntoIterator<Item = T>>(iter: It) -> Self {
        Self {
            _marker: PhantomData,
            inner: iter.into_iter().collect(),
        }
    }
}

impl<I: ArenaIndex, T> std::ops::Index<I> for IndexedArena<I, T> {
    type Output = T;

    fn index(&self, index: I) -> &Self::Output {
        &self.inner[index.to_index()]
    }
}

pub trait ArenaIndex {
    fn to_index(self) -> usize;
    fn from_index(index: usize) -> Self;
}
