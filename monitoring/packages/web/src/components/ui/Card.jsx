import { cn } from '@/lib/utils';

export const Card = ({ className, ...props }) => (
  <div className={cn('relative rounded-[4px] border border-border bg-gradient-to-b from-card to-[#0c0e12]', className)} {...props} />
);
