//go:build !go1.16
// +build !go1.16

package engine

// Static implements `Engine#Static()` for sub-routes within the Group.
func (g *Group) Static(prefix, root string) {
	g.static(prefix, root, g.GET)
}
