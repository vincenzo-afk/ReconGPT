declare module "lucide-react/dist/esm/icons/*" {
  import type { ForwardRefExoticComponent, RefAttributes, SVGProps } from "react";
  type LucideProps = Omit<SVGProps<SVGSVGElement>, "ref"> & {
    size?: string | number;
    absoluteStrokeWidth?: boolean;
  };
  const Icon: ForwardRefExoticComponent<LucideProps & RefAttributes<SVGSVGElement>>;
  export default Icon;
}
