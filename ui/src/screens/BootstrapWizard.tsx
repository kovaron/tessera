interface Props { onDone: () => void; }
export default function BootstrapWizard({ onDone }: Props) {
  return <div className="p-6">Bootstrap wizard (todo) <button onClick={onDone}>continue</button></div>;
}
