type Props = {
  /** The size of the icon, 24px is default to match standard icons */
  size?: number;
  /** The color of the icon, defaults to the current text color */
  color?: string;
};

/** Two-peak summit mark used for the "Continue with TRA" sign-in button. */
export default function TRAIcon({ size = 24, color = "currentColor" }: Props) {
  return (
    <svg fill={color} width={size} height={size} viewBox="0 0 24 24">
      <path d="M14.5 5 L21 19 H3 L8.5 8.5 L11 12.5 Z M14.5 8.9 L12.2 13.5 L13.6 15.8 L15.4 15.8 L14.5 17.2 L11.3 17.2 L9.6 14.4 L8.5 12.3 L6.3 17 H17.9 Z" />
    </svg>
  );
}
