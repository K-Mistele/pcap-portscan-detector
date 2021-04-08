package set

type Set struct {
	items	map[interface{}] bool

}

// ADD AN ITEM TO A SET
func (s *Set) Add(item interface{}) {
	if s.items == nil {
		s.items = make(map[interface{}] bool)
	}
	s.items[item] = true
}

// REMOVE AN ITEM FROM THE SET
func (s *Set) Delete(item interface{}) {
	if s.items == nil {
		s.items = make(map[interface{}] bool)
	}
	delete(s.items, item)
}


// GET A LIST OF ITEMS
func (s Set) Items() []interface{} {
	if s.items == nil {
		s.items = make(map[interface{}] bool)
	}
	keys := make([]interface{}, len(s.items))
	i := 0
	for key := range s.items {
		keys[i] = key
		i++
	}
	return keys
}

// GET THE SIZE
func (s Set) Size() int {
	return len(s.items)
}
