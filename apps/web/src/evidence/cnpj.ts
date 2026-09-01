/** Numeric CNPJ checksum only: never an official registry or ownership check. */
export function normalizeCnpj(value: string): string {
  return value.replace(/[.\s/-]/g, "");
}
export function validCnpj(input: string): boolean {
  const value = normalizeCnpj(input);
  if (!/^\d{14}$/.test(value) || /^(\d)\1+$/.test(value)) return false;
  const digit = (length: number) => {
    let sum = 0;
    let weight = length - 7;
    for (let i = 0; i < length; i++) {
      sum += Number(value[i]) * weight;
      weight = weight === 2 ? 9 : weight - 1;
    }
    const remainder = sum % 11;
    return remainder < 2 ? 0 : 11 - remainder;
  };
  return digit(12) === Number(value[12]) && digit(13) === Number(value[13]);
}
export function formatCnpj(value: string): string {
  return normalizeCnpj(value).replace(
    /^(\d{2})(\d{3})(\d{3})(\d{4})(\d{2})$/,
    "$1.$2.$3/$4-$5",
  );
}
export interface CnpjObservation {
  value: string;
  checksum: "VALID" | "INVALID";
  provenance: {
    url: string;
    location: "FOOTER" | "PAGE" | "STRUCTURED_DATA";
  }[];
}
