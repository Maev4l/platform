import { cva } from 'class-variance-authority';
import { cn } from '@/lib/utils';

const button = cva(
  'inline-flex items-center justify-center gap-2 rounded-[4px] font-mono transition-colors disabled:opacity-50',
  {
    variants: {
      variant: {
        default: 'bg-signal text-[#0b0d07] hover:bg-signal/90',
        outline: 'border border-border bg-card text-foreground hover:border-signal/60',
      },
      size: { default: 'h-9 px-4 text-sm', sm: 'h-7 px-2.5 text-[10px] uppercase tracking-[0.12em]' },
    },
    defaultVariants: { variant: 'default', size: 'default' },
  }
);

export const Button = ({ className, variant, size, ...props }) => (
  <button className={cn(button({ variant, size }), className)} {...props} />
);
