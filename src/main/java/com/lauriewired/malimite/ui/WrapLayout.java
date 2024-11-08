package com.lauriewired.malimite.ui;

import java.awt.*;

public class WrapLayout extends FlowLayout {
    public WrapLayout(int align, int hgap, int vgap) {
        super(align, hgap, vgap);
    }

    @Override
    public Dimension preferredLayoutSize(Container target) {
        return layoutSize(target, true);
    }

    @Override
    public Dimension minimumLayoutSize(Container target) {
        return layoutSize(target, false);
    }

    private Dimension layoutSize(Container target, boolean preferred) {
        synchronized (target.getTreeLock()) {
            int width = target.getWidth();
            if (width == 0) width = Integer.MAX_VALUE;
            
            Insets insets = target.getInsets();
            int maxWidth = width - (insets.left + insets.right);
            int x = insets.left;
            int y = insets.top;
            int rowHeight = 0;

            int nmembers = target.getComponentCount();
            for (int i = 0; i < nmembers; i++) {
                Component m = target.getComponent(i);
                if (m.isVisible()) {
                    Dimension d = preferred ? m.getPreferredSize() : m.getMinimumSize();
                    if (x > insets.left && x + d.width > maxWidth) {
                        x = insets.left;
                        y += rowHeight + getVgap();
                        rowHeight = 0;
                    }
                    x += d.width + getHgap();
                    rowHeight = Math.max(rowHeight, d.height);
                }
            }
            return new Dimension(width, y + rowHeight + insets.bottom);
        }
    }
} 